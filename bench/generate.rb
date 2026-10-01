#!/usr/bin/env ruby
# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'redhound'
require 'optparse'
require 'fileutils'
options = { packets: 200_000, out: 'tmp/bench.pcap' }
OptionParser.new do |parser|
  parser.on('--packets N', Integer) { |value| options[:packets] = value }
  parser.on('--out FILE') { |value| options[:out] = value }
end.parse!
abort 'packet count must be positive' unless options[:packets].positive?
FileUtils.mkdir_p File.dirname(options[:out])
payload = 'x'.b * 546
Redhound::Writer.open(options[:out]) do |writer|
  options[:packets].times do |index|
    transport = index.even? ? [40000, 9999, 8 + payload.bytesize, 0].pack('n4') + payload : [40000, 9999, index, 0, 0x5018, 64240, 0, 0].pack('nnNNn4') + payload
    ip = [0x45, 0, 20 + transport.bytesize, index & 0xffff, 0, 64, index.even? ? 17 : 6, 0, 0xc0000201, 0xc6336401].pack('CCnnnCCnNN')
    ip[10, 2] = [Redhound::Protocols::Checksum.value(ip)].pack('n')
    bytes = ['0200000000020200000000010800'].pack('H*') + ip + transport
    writer << Redhound::Packet.new(bytes, timestamp_ns: 1_700_000_000_000_000_000 + index * 1000, number: index + 1)
  end
end
