# frozen_string_literal: true
require 'spec_helper'
require 'redhound/filter'
require 'open3'
require 'tmpdir'

RSpec.describe 'native capture filters versus tcpdump', :differential do
  FilterPacket = Struct.new(:data, :original_length, :linktype, :meta)
  FILTERS = File.readlines(File.join(__dir__, 'filters.txt'), chomp: true).reject { |line| line.empty? || line.start_with?('#') }.freeze

  def corpus(linktype)
    payloads = []
    %w[192.0.2.1 198.51.100.1 127.0.0.1].each do |src|
      %w[192.0.2.2 192.0.2.1 224.0.0.1 255.255.255.255 0.0.0.0].each do |dst|
        [[6, tcp(dport: 80)], [6, tcp(dport: 443, flags: 0x12)], [17, udp('x'.b)],
         [17, udp('x'.b, sport: 53, dport: 53)], [17, udp('x'.b, dport: 80)],
         [1, icmp_echo], [2, "\x11" * 8], [132, tcp(dport: 443)]].each do |proto, transport|
          payloads << [0x0800, ipv4(transport, src: src, dst: dst, proto: proto)]
        end
      end
    end
    %w[2001:db8::1 2001:db9::1].each do |src|
      %w[2001:db8::2 2001:db8::1 ff02::1].each do |dst|
        [[6, tcp(dport: 443)], [17, udp('x'.b)], [58, "\x80".b * 8], [132, tcp(dport: 443)]].each do |proto, transport|
          payloads << [0x86dd, ipv6(transport, src: src, dst: dst, next_header: proto)]
        end
      end
    end
    fragment = ipv4(udp('x'.b)); fragment[6, 2] = [1].pack('n')
    payloads << [0x0800, fragment]
    fragment0 = ipv4(udp('x'.b)); fragment0[6, 2] = [0x2000].pack('n')
    payloads << [0x0800, fragment0]
    payloads << [0x0800, ipv4(udp('x'.b), options: "\x01\x01\x01\x00".b)]
    [6, 17, 58].each do |proto|
      payloads << [0x86dd, ipv6([proto, 0, 0, 1].pack('CCnN') + tcp(dport: 443), next_header: 44)]
      payloads << [0x86dd, ipv6([proto, 0, 8, 1].pack('CCnN') + tcp(dport: 443), next_header: 44)]
    end
    payloads << [0x0806, arp]
    payloads << [0x8035, arp]
    packets = payloads.filter_map do |type, payload|
      data = case linktype
             when 1 then ether(payload, type: type)
             when 101 then next unless [0x0800, 0x86dd].include?(type); payload
             when 113 then [0, 1, 6].pack('nnn') + mac('02:00:00:00:00:01').ljust(8, "\0") + [type].pack('n') + payload
             when 276 then [type, 0, 1, 1, 0, 6].pack('nnNnCC') + mac('02:00:00:00:00:01').ljust(8, "\0") + payload
             when 0 then next unless [0x0800, 0x86dd].include?(type); [type == 0x0800 ? 2 : 30].pack('L') + payload
             end
      FilterPacket.new(data, data.bytesize, linktype, {})
    end
    if linktype == 1
      [0, 100, 200].each do |id|
        packets << FilterPacket.new(ether([id, 0x0800].pack('nn') + ipv4(udp('x'.b)), type: 0x8100), 60, 1, {})
        packets << FilterPacket.new(ether([id, 0x86dd].pack('nn') + ipv6(udp('x'.b)), type: 0x88a8), 66, 1, {})
      end
      packets << FilterPacket.new(ether([100, 0x8100, 200, 0x0800].pack('nnnn') + ipv4(udp('x'.b)), type: 0x8100), 60, 1, {})
      packets << FilterPacket.new("\0" * 10, 60, 1, {})
      packets << FilterPacket.new(packets.first.data.byteslice(0, 25), 300, 1, {})
    end
    packets.each { |packet| packet.original_length = [packet.original_length, packet.data.bytesize].max }
    packets
  end

  def write_pcap(path, packets, linktype)
    File.open(path, 'wb') do |file|
      file.write([0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype].pack('VvvVVVV'))
      packets.each_with_index do |packet, index|
        file.write([index + 1, 0, packet.data.bytesize, packet.original_length].pack('V4'))
        file.write(packet.data)
      end
    end
  end

  before(:all) do
    @tcpdump = (ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).map { |path| File.join(path, 'tcpdump') } + ['/usr/sbin/tcpdump']).find { |path| File.executable?(path) }
  end

  it 'provides at least 100 compatibility expressions' do
    expect(FILTERS.size).to be >= 100
  end

  [1, 101, 113, 276, 0].each do |linktype|
    it "matches tcpdump selected packets and executes tcpdump bytecode for linktype #{linktype}" do
      skip 'tcpdump is required for differential filters' unless @tcpdump
      packets = corpus(linktype)
      expressions = linktype == 1 ? FILTERS : FILTERS.reject { |expr| expr.match?(/\bether\b|\bvlan\b/) }
      Dir.mktmpdir('redhound-filters') do |directory|
        path = File.join(directory, 'packets.pcap')
        write_pcap(path, packets, linktype)
        expressions.each do |expression|
          output, error, status = Open3.capture3(@tcpdump, '-O', '-nn', '-tt', '-r', path, '--', expression)
          expect(status.success?).to be(true), "tcpdump rejected #{expression.inspect}: #{error}"
          expected = output.lines.filter_map { |line| line.split.first.to_i - 1 if line.match?(/\A\d+\.\d+ /) }
          program = Redhound::Filter.compile(expression, linktype: linktype)
          actual = packets.each_index.select { |index| program.match?(packets[index]) }
          expect(actual).to eq(expected), "match mismatch for #{expression.inspect} / linktype #{linktype}: extra #{actual - expected}, missing #{expected - actual}"
          decimal, error, status = Open3.capture3(@tcpdump, '-O', '-ddd', '-r', path, '--', expression)
          expect(status.success?).to be(true), "tcpdump compilation failed #{expression.inspect}: #{error}"
          reference = Redhound::Filter::Program.new(decimal.lines.drop(1).map { |line| line.split.map(&:to_i) }, linktype: linktype)
          expect(packets.each_index.select { |index| reference.match?(packets[index]) }).to eq(expected), "VM mismatch for #{expression.inspect}"
        end
      end
    end
  end
end
