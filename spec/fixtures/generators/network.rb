# frozen_string_literal: true

# Fixed public documentation addresses and timestamps make these wire fixtures reproducible.
module NetworkFixtures
  module_function

  def message_checksum(bytes, offset: 2)
    bytes = bytes.dup
    bytes[offset, 2] = [checksum(bytes)].pack('n')
    bytes
  end

  def transport_checksum(bytes, proto, ipv6: false)
    bytes = bytes.dup
    pseudo = if ipv6
               ip6('2001:db8::1') + ip6('2001:db8::2') + [bytes.bytesize, proto].pack('Nx3C')
             else
               ip4('192.0.2.1') + ip4('192.0.2.2') + [0, proto, bytes.bytesize].pack('CCn')
             end
    bytes[proto == 6 ? 16 : proto == 17 ? 6 : 2, 2] = [checksum(pseudo + bytes)].pack('n')
    bytes
  end

  def tcp_options(options, **args)
    raise ArgumentError, 'TCP options must be aligned and fit a TCP header' unless options.bytesize % 4 == 0 && options.bytesize <= 40
    bytes = tcp(''.b, **args)
    bytes.setbyte(12, (5 + options.bytesize / 4) << 4)
    bytes + options
  end

  def network_frames
    u = udp('network', dport: 9999)
    inner = ipv4(u)
    echo6 = transport_checksum([128, 0, 0, 7, 9].pack('CCnnn') + 'ping', 58, ipv6: true)
    ns = [135, 0, 0, 0].pack('CCnN') + ip6('2001:db8::2') + [1, 1].pack('CC') + mac('02:00:00:00:00:01')
    na = [136, 0, 0, 0xe0000000].pack('CCnN') + ip6('2001:db8::2') + [2, 1].pack('CC') + mac('02:00:00:00:00:02')
    prefix = [3, 4, 64, 0xc0, 3600, 1800, 0].pack('C4N3') + ip6('2001:db8::')
    ra = [134, 0, 0, 64, 0xc0, 1800, 1000, 2000].pack('CCnCCnNN') + prefix + [5, 1, 0, 1500].pack('CCnN')
    redirect = [137, 0, 0, 0].pack('CCnN') + ip6('2001:db8::1') + ip6('2001:db8::2')
    query3 = [0x11, 10, 0, 0xef010101, 2, 125, 1, 0xc0000201].pack('CCnNCCnN')
    report3 = [0x22, 0, 0, 0, 1, 1, 0, 1, 0xef010101, 0xc0000201].pack('CCnnnCCnNN')
    handshake_options = [2, 4, 1460, 1, 3, 3, 7, 4, 2, 8, 10, 123456, 654321].pack('CCnCCCCCCCCNN').ljust(24, "\0")
    sack_tfo = [5, 10, 1000, 2000, 34, 6].pack('CCNNCC') + "abcd"
    extension_chain = [43, 0].pack('CC') + "\0" * 6 + [60, 0].pack('CC') + "\0" * 6 +
                      [51, 0].pack('CC') + "\0" * 6 + [17, 1].pack('CC') + "\0" * 10
    quoted = [3, 3, 0, 0].pack('CCnN') + inner
    quoted[2, 2] = [checksum(quoted)].pack('n')
    {
      arp: ether(arp, type: 0x0806),
      ipv4_udp: ether(ipv4(transport_checksum(u, 17))),
      ipv6_udp: ether(ipv6(transport_checksum(u, 17, ipv6: true)), type: 0x86dd),
      vlan: ether([0xb064, 0x0800].pack('n2') + inner, type: 0x8100),
      qinq: ether([100, 0x8100, 200, 0x0800].pack('n4') + inner, type: 0x88a8),
      snap: ether([0xaa, 0xaa, 3, 0, 0, 0, 0x0800].pack('C6n') + inner, type: 8 + inner.bytesize),
      llc: ether([0x42, 0x42, 3].pack('C3') + 'payload', type: 10),
      ipv4_options: ether(ipv4(u, options: [1, 1, 0, 0].pack('C4'))),
      ipv6_extensions: ether(ipv6(extension_chain + u, next_header: 0), type: 0x86dd),
      ipv6_fragment: ether(ipv6([17, 0, 0, 123].pack('CCnN') + u, next_header: 44), type: 0x86dd),
      ipv6_esp: ether(ipv6([123, 1].pack('N2') + 'encrypted', next_header: 50), type: 0x86dd),
      icmp_echo: ether(ipv4(icmp_echo, proto: 1)),
      icmp_error: ether(ipv4(quoted, proto: 1)),
      icmpv6_echo: ether(ipv6(echo6, next_header: 58), type: 0x86dd),
      ndp_ns: ether(ipv6(transport_checksum(ns, 58, ipv6: true), next_header: 58), type: 0x86dd),
      ndp_na: ether(ipv6(transport_checksum(na, 58, ipv6: true), next_header: 58), type: 0x86dd),
      ndp_rs: ether(ipv6(transport_checksum([133, 0, 0, 0].pack('CCnN'), 58, ipv6: true), next_header: 58), type: 0x86dd),
      ndp_ra: ether(ipv6(transport_checksum(ra, 58, ipv6: true), next_header: 58), type: 0x86dd),
      ndp_redirect: ether(ipv6(transport_checksum(redirect, 58, ipv6: true), next_header: 58), type: 0x86dd),
      igmp_v1: ether(ipv4(message_checksum([0x12, 0, 0, 0xef010101].pack('CCnN')), proto: 2)),
      igmp_v2: ether(ipv4(message_checksum([0x16, 0, 0, 0xef010101].pack('CCnN')), proto: 2)),
      igmp_v3_query: ether(ipv4(message_checksum(query3), proto: 2)),
      igmp_v3_report: ether(ipv4(message_checksum(report3), proto: 2)),
      tcp_options: ether(ipv4(transport_checksum(tcp_options(handshake_options, dport: 9999, seq: 0x12345678, ack: 0x87654321, flags: 0xc2), 6), proto: 6)),
      tcp_sack_tfo: ether(ipv4(transport_checksum(tcp_options(sack_tfo, dport: 9999, seq: 0x87654321, ack: 0x12345678, flags: 0x10), 6), proto: 6)),
      gre: ether(ipv4(message_checksum([0xb000, 0x0800, 0, 42, 7].pack('nnN3') + inner, offset: 4), proto: 47)),
      gre_ethernet: ether(ipv4([0, 0x6558].pack('n2') + ether(inner), proto: 47)),
      vxlan: ether(ipv4(udp([0x08000000, 42 << 8].pack('N2') + ether(inner), dport: 4789)))
    }
  end

  def linktype_frames
    v4, v6 = ipv4(udp('network', dport: 9999)), ipv6(udp('network', dport: 9999))
    {
      sll: [113, [0, 1, 6].pack('n3') + mac('02:00:00:00:00:01') + "\0\0" + [0x0800].pack('n') + v4],
      sll2: [276, [0x86dd, 0, 3, 1, 0, 6].pack('nnNnCC') + mac('02:00:00:00:00:01') + "\0\0" + v6],
      null_v4: [0, [2].pack('L') + v4],
      null_v6: [0, [24].pack('L') + v6],
      loop: [108, [2].pack('N') + v4],
      raw_v4: [101, v4], raw_v6: [101, v6], ipv4_linktype: [228, v4], ipv6_linktype: [229, v6]
    }
  end

  def network_packets
    network_frames.values.each_with_index.map do |bytes, index|
      Redhound::Packet.new(bytes, timestamp_ns: 1_700_000_000_000_000_000 + index * 1_000_000, number: index + 1)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  require_relative '../../../lib/redhound'
  require_relative '../../support/packet_factory'
  factory = Object.new.extend(PacketFactory).extend(NetworkFixtures)
  path = File.expand_path('../pcap/network.pcap', __dir__)
  writer = Redhound::File::PcapWriter.new(path)
  factory.instance_eval { network_packets.each { |packet| writer.write(packet) } }
  writer.close
end
