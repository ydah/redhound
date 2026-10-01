# frozen_string_literal: true

require_relative 'applications'

# Fixed timestamps, addresses, checksums and sequence numbers make tshark's
# timing-dependent TCP classification repeatable.
module AnalysisFixtures
  include ApplicationFixtures

  def analysis_tcp(data = ''.b, seq:, ack: 0, flags: 0x10, reverse: false, window: 64_240, sport: 40_000, dport: 9999, at: 0)
    src, dst = reverse ? ['192.0.2.2', '192.0.2.1'] : ['192.0.2.1', '192.0.2.2']
    ports = reverse ? [dport, sport] : [sport, dport]
    segment = tcp(data, sport: ports[0], dport: ports[1], seq: seq % (1 << 32), ack: ack % (1 << 32), flags: flags, window: window)
    pseudo = ip4(src) + ip4(dst) + [0, 6, segment.bytesize].pack('CCn')
    segment[16, 2] = [checksum(pseudo + segment)].pack('n')
    Redhound::Packet.new(ether(ipv4(segment, src: src, dst: dst, proto: 6)), timestamp_ns: 1_700_000_000_000_000_000 + at)
  end

  def analysis_tcp_packets
    isn, server = 0xffff_fff0, 5000
    packets = [
      analysis_tcp(seq: isn, flags: 2),
      analysis_tcp(seq: server, ack: isn + 1, flags: 0x12, reverse: true, at: 10_000_000),
      analysis_tcp(seq: isn + 1, ack: server + 1, at: 20_000_000),
      analysis_tcp("ab\0\xffef".b, seq: isn + 1, ack: server + 1, flags: 0x18, at: 100_000_000),
      analysis_tcp("ab\0\xffef".b, seq: isn + 1, ack: server + 1, flags: 0x18, at: 500_000_000),
      analysis_tcp(seq: server + 1, ack: isn + 7, reverse: true, at: 510_000_000),
      analysis_tcp(seq: server + 1, ack: isn + 7, reverse: true, at: 520_000_000),
      analysis_tcp(seq: server + 1, ack: isn + 7, reverse: true, window: 0, at: 530_000_000),
      analysis_tcp(seq: server + 1, ack: isn + 7, reverse: true, at: 540_000_000),
      analysis_tcp('mnopqrst', seq: isn + 13, ack: server + 1, flags: 0x18, at: 550_000_000),
      analysis_tcp('ghijkl', seq: isn + 7, ack: server + 1, flags: 0x18, at: 551_000_000),
      analysis_tcp(seq: server + 1, ack: isn + 21, reverse: true, at: 560_000_000),
      analysis_tcp("\0", seq: isn + 20, ack: server + 1, at: 1_000_000_000),
      analysis_tcp(seq: server + 1, ack: isn + 21, reverse: true, at: 1_010_000_000),
      analysis_tcp(seq: isn + 21, ack: server + 1, flags: 0x11, at: 1_100_000_000),
      analysis_tcp(seq: server + 1, ack: isn + 22, reverse: true, at: 1_110_000_000),
      analysis_tcp(seq: server + 1, ack: isn + 22, flags: 0x11, reverse: true, at: 1_120_000_000),
      analysis_tcp(seq: isn + 22, ack: server + 2, at: 1_130_000_000)
    ]
    renumber_analysis(packets)
  end

  def analysis_stats_packets
    packets = [analysis_tcp(seq: 100, flags: 2),
               analysis_tcp(seq: 500, ack: 101, flags: 0x12, reverse: true, at: 10_000_000),
               analysis_tcp(seq: 101, ack: 501, at: 20_000_000),
               analysis_tcp('client', seq: 101, ack: 501, flags: 0x18, at: 30_000_000),
               analysis_tcp('server', seq: 501, ack: 107, flags: 0x18, reverse: true, at: 1_100_000_000)]
    [[false, false], [false, true], [true, false], [true, true]].each_with_index do |(v6, reverse), index|
      src, dst = v6 ? ['2001:db8::1', '2001:db8::2'] : ['192.0.2.1', '192.0.2.2']
      src, dst = dst, src if reverse
      segment = udp('datagram', sport: reverse ? 9998 : 40_001, dport: reverse ? 40_001 : 9998)
      pseudo = v6 ? ip6(src) + ip6(dst) + [segment.bytesize, 17].pack('Nx3C') : ip4(src) + ip4(dst) + [0, 17, segment.bytesize].pack('CCn')
      segment[6, 2] = [checksum(pseudo + segment)].pack('n')
      network = v6 ? ipv6(segment, src: src, dst: dst) : ipv4(segment, src: src, dst: dst)
      frame = ether(network, type: v6 ? 0x86dd : 0x0800, src: reverse ? '02:00:00:00:00:02' : '02:00:00:00:00:01', dst: reverse ? '02:00:00:00:00:01' : '02:00:00:00:00:02')
      packets << Redhound::Packet.new(frame, timestamp_ns: 1_700_000_000_000_000_000 + 1_200_000_000 + index * 100_000_000)
    end
    renumber_analysis(packets)
  end

  def analysis_reassembly_packets
    packets = []
    [false, true].each do |v6|
      datagram = udp(dns([], flags: 0), sport: 40_002, dport: 53)
      pseudo = v6 ? ip6('2001:db8::1') + ip6('2001:db8::2') + [datagram.bytesize, 17].pack('Nx3C') : ip4('192.0.2.1') + ip4('192.0.2.2') + [0, 17, datagram.bytesize].pack('CCn')
      datagram[6, 2] = [checksum(pseudo + datagram)].pack('n')
      [[24, false, datagram.byteslice(24..)], [0, true, datagram.byteslice(0, 24)]].each do |offset, more, data|
        if v6
          network = ipv6([17, 0, offset | (more ? 1 : 0), 42].pack('CCnN') + data, next_header: 44)
        else
          network = ipv4(data, id: 42)
          network[6, 2] = [(offset / 8) | (more ? 0x2000 : 0)].pack('n')
          network[10, 2] = "\0\0"
          network[10, 2] = [checksum(network.byteslice(0, 20))].pack('n')
        end
        packets << Redhound::Packet.new(ether(network, type: v6 ? 0x86dd : 0x0800), timestamp_ns: 1_700_000_000_000_000_000 + packets.size * 10_000_000)
      end
    end
    [["GET /stream HTTP/1.1\r\nHost: example.test\r\n\r\n", 80, 12],
     [tls_record(tls_hello), 443, 30], [[dns([], flags: 0).bytesize].pack('n') + dns([], flags: 0), 53, 1]].each_with_index do |(message, port, split), index|
      sport = 40_010 + index
      packets << analysis_tcp(seq: 99, flags: 2, sport: sport, dport: port, at: packets.size * 10_000_000)
      packets << analysis_tcp(seq: 500, ack: 100, flags: 0x12, reverse: true, sport: sport, dport: port, at: packets.size * 10_000_000)
      packets << analysis_tcp(seq: 100, ack: 501, sport: sport, dport: port, at: packets.size * 10_000_000)
      [message.byteslice(0, split), message.byteslice(split, split), message.byteslice(split * 2..)].each_with_object([100]) do |data, sequence|
        packets << analysis_tcp(data, seq: sequence[0], ack: 501, flags: 0x18, sport: sport, dport: port, at: packets.size * 10_000_000)
        sequence[0] += data.bytesize
      end
    end
    renumber_analysis(packets)
  end

  def renumber_analysis(packets)
    packets.each_with_index.map do |packet, index|
      Redhound::Packet.new(packet.data, timestamp_ns: packet.timestamp_ns, number: index + 1)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  require_relative '../../../lib/redhound'
  require_relative '../../support/packet_factory'
  factory = Object.new.extend(PacketFactory).extend(AnalysisFixtures)
  { tcp: factory.analysis_tcp_packets, stats: factory.analysis_stats_packets, reassembly: factory.analysis_reassembly_packets }.each do |name, packets|
    writer = Redhound::File::PcapWriter.new(File.expand_path("../pcap/analysis-#{name}.pcap", __dir__))
    packets.each { |packet| writer.write(packet) }
    writer.close
  end
end
