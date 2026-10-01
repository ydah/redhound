#!/usr/bin/env ruby
# frozen_string_literal: true

# Exercise the default 256 MiB aggregate, 16 MiB IP and 64 MiB TCP limits.
# Accounted state is a conservative bound on retained analysis objects. Ruby
# heap includes the whole process; RSS also includes allocator pages and may
# remain high after buffers are freed. Neither is the accounted-state limit.
require 'objspace'
require_relative '../lib/redhound'
require_relative '../lib/redhound/analysis'
require_relative '../spec/support/packet_factory'
include PacketFactory
$stdout.sync = true

def rss_bytes
  if File.readable?('/proc/self/status')
    File.read('/proc/self/status')[/^VmRSS:\s+(\d+)\s+kB/, 1]&.to_i&.*(1024)
  elsif RUBY_PLATFORM.include?('darwin')
    IO.popen(['ps', '-o', 'rss=', '-p', Process.pid.to_s], &:read).to_i * 1024
  end
end

session = Redhound::Analysis::Session.new(stats: ['conv,udp', 'endpoints,udp', 'phs', 'io,1'])
peak = 0
inspect_packet = lambda do |packet|
  session.update(packet)
  peak = [peak, session.bytesize].max
  raise "global state bound exceeded: #{session.bytesize}" if session.bytesize > 256 << 20
  raise 'IP state bound exceeded' if session.ip_reassembler.bytesize > 16 << 20
  raise 'TCP state bound exceeded' if session.flows.tcp_bytesize > 64 << 20
  raise 'flow count exceeded' if session.flows.size > 100_000
end
report = lambda do |phase|
  GC.start
  puts({ phase: phase, accounted_state_bytes: session.bytesize, peak_accounted_state_bytes: peak,
         ruby_heap_bytes: ObjectSpace.memsize_of_all, rss_bytes: rss_bytes,
         flows: session.flows.size, evicted_flows: session.flows.evicted,
         fragmented_datagrams: session.ip_reassembler.size,
         ip_bytes: session.ip_reassembler.bytesize, tcp_bytes: session.flows.tcp_bytesize }.inspect)
end
report.call(:baseline)
60_000.times do |index|
  inspect_packet.call(Redhound::Packet.new(ether(ipv4(udp('pressure', dport: 1024 + index)))))
end
report.call(:many_udp_and_statistics)
40_000.times do |index|
  bytes = ipv4('abcdefgh', id: index)
  bytes[6, 2] = [0x2000].pack('n')
  inspect_packet.call(Redhound::Packet.new(ether(bytes)))
end
report.call(:many_fragment_identities)
80.times do |index|
  13.times do |part|
    bytes = tcp('x' * 40_000, seq: 100 + part * 40_000, flags: 0x18, dport: 10_000 + index)
    inspect_packet.call(Redhound::Packet.new(ether(ipv4(bytes, proto: 6))))
  end
end
report.call(:large_tcp_streams)
File.open(File::NULL, 'wb') { |sink| session.finish(sink, sink) }
raise 'IP buffers retained after finish' unless session.ip_reassembler.bytesize.zero?
raise 'TCP buffers retained after finish' unless session.flows.tcp_bytesize.zero?
session.flows.values.each do |flow|
  raise 'application buffers retained after finish' unless flow.applications.compact.sum(&:bytesize).zero?
  raise 'HTTP context retained after finish' unless flow.http_methods.all?(&:empty?)
  raise 'detection buffers retained after finish' unless flow.probes.all?(&:empty?)
end
report.call(:finished)
