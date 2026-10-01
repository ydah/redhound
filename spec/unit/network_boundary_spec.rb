# frozen_string_literal: true

require_relative '../fixtures/generators/network'

RSpec.describe 'network protocol boundaries' do
  include NetworkFixtures

  def codes(packet, protocol = nil)
    (protocol ? packet.layers_of(protocol) : packet.layers).flat_map { |layer| layer.diagnostics.map(&:code) }
  end

  def checked(bytes, **metadata)
    packet = Redhound::Packet.new(bytes, **metadata)
    packet.engine = Redhound::Engine.new(verify_checksums: true)
    packet
  end

  it 'decodes the entire deterministic network corpus without parser errors' do
    path = File.expand_path('../fixtures/pcap/network.pcap', __dir__)
    expect(Redhound.open(path).map(&:data)).to eq(network_frames.values)
    network_frames.each do |name, bytes|
      packet = Redhound.dissect(bytes)
      expect(packet.layers.flat_map(&:diagnostics).select { |d| d.severity == :error }).to be_empty, name.to_s
    end
  end

  it 'turns every corpus truncation into bounded layers without an internal parser error' do
    network_frames.each do |name, bytes|
      (0...bytes.bytesize).each do |length|
        packet = Redhound.dissect(bytes.byteslice(0, length), original_length: bytes.bytesize)
        expect(codes(packet)).not_to include(:dissector_bug), "#{name} truncated at #{length}"
        expect(packet.layers.all? { |layer| layer.offset <= length && layer.payload_end <= length }).to be(true), "#{name} truncated at #{length}"
      end
    end
  end

  it 'respects the declared 802.3 frame length instead of interpreting Ethernet padding' do
    frame = ether([0x42, 0x42, 3].pack('C3') + 'abc', type: 6)
    packet = Redhound.dissect(frame)
    expect(packet[:llc][:dsap]).to eq(0x42)
    expect(packet['data.data']).to eq('abc')
  end

  it 'stops SNAP dispatch for a vendor OUI it does not support' do
    frame = ether([0xaa, 0xaa, 3, 1, 2, 3, 0x0800].pack('C6n') + ipv4(udp('x', dport: 9999)), type: 37)
    packet = Redhound.dissect(frame)
    expect(packet[:ipv4]).to be_nil
    expect(packet['llc.oui']).to eq("\x01\x02\x03".b)
  end

  it 'recognizes every supported link type and rejects an unknown raw IP version' do
    linktype_frames.each do |name, (linktype, bytes)|
      packet = Redhound.dissect(bytes, linktype: linktype)
      expect(packet['udp.dstport']).to eq(9999), name.to_s
      expect(codes(packet)).not_to include(:dissector_bug)
    end
    expect(Redhound.dissect("\x70unknown", linktype: 101)[:data]).not_to be_nil
    expect(Redhound.dissect([99].pack('L') + 'unknown', linktype: 0)[:data]).not_to be_nil
    expect(Redhound.dissect([2].pack('N') + ipv4(udp('x', dport: 9999)), linktype: 0)['ip.version']).to eq(4)
  end

  it 'reports each fixed network header when it is only partially captured' do
    { vlan: [0x8100, "\0"], arp: [0x0806, "\0"], ipv4: [0x0800, "\x45"], ipv6: [0x86dd, "\x60"] }.each do |protocol, (type, payload)|
      expect(codes(Redhound.dissect(ether(payload, type: type, pad: false)), protocol)).to include(:truncated)
    end
    { tcp: [6, 19], udp: [17, 7], icmp: [1, 7], igmp: [2, 7], gre: [47, 3] }.each do |protocol, (proto, size)|
      expect(codes(Redhound.dissect(ether(ipv4("\0" * size, proto: proto), pad: false)), protocol)).to include(:truncated)
    end
    expect(codes(Redhound.dissect(ether(ipv4(udp("\0" * 7, dport: 4789)), pad: false)), :vxlan)).to include(:truncated)
  end

  it 'rejects IPv4 version, header length and total length inconsistencies' do
    [0x35, 0x44].each do |version_ihl|
      bytes = ipv4(udp('x', dport: 9999))
      bytes.setbyte(0, version_ihl)
      packet = Redhound.dissect(ether(bytes))
      expect(codes(packet, :ipv4)).to include(:bad_length)
      expect(packet[:udp]).to be_nil
    end
    bytes = ipv4(udp('x', dport: 9999), options: "\1\1\0\0")
    bytes[2, 2] = [20].pack('n')
    expect(codes(Redhound.dissect(ether(bytes)), :ipv4)).to include(:bad_length)
  end

  it 'keeps IPv4 options within the IHL and payload within total length' do
    packet = Redhound.dissect(network_frames.fetch(:ipv4_options))
    expect(packet['ip.options']).to eq("\1\1\0\0")
    expect(packet[:udp].offset).to eq(38)
    expect(packet['data.data']).to eq('network')
    truncated = ipv4(''.b, options: "\1\1\0\0").byteslice(0, 22)
    expect(codes(Redhound.dissect(ether(truncated, pad: false)), :ipv4)).to include(:truncated)
  end

  it 'does not mistake noninitial IPv4 fragments for transport headers' do
    bytes = ipv4('fragment', proto: 6)
    bytes[6, 2] = [0x2002].pack('n')
    packet = Redhound.dissect(ether(bytes))
    expect(packet['ip.flags.mf']).to eq(1)
    expect(packet['ip.frag_offset']).to eq(16)
    expect(packet[:tcp]).to be_nil
  end

  it 'rejects an IPv6 version mismatch and bounds extension chains at 16' do
    bytes = ipv6(udp('x', dport: 9999))
    bytes.setbyte(0, 0x50)
    expect(codes(Redhound.dissect(ether(bytes, type: 0x86dd)), :ipv6)).to include(:malformed)
    extensions = ([0, 0].pack('CC') + "\0" * 6) * 17
    packet = Redhound.dissect(ether(ipv6(extensions + udp('x', dport: 9999), next_header: 0), type: 0x86dd))
    expect(packet.layers_of(:ipv6_ext).length).to eq(17)
    expect(codes(packet, :ipv6_ext)).to include(:malformed)
    expect(packet[:udp]).to be_nil
  end

  it 'parses all extension sizes, stops at ESP and distinguishes noninitial IPv6 fragments' do
    packet = Redhound.dissect(network_frames.fetch(:ipv6_extensions))
    expect(packet.field_values('ipv6.extension.type')).to eq([0, 43, 60, 51])
    expect(packet.layers_of(:ipv6_ext).map(&:header_length)).to eq([8, 8, 8, 12])
    expect(packet['udp.dstport']).to eq(9999)
    expect(Redhound.dissect(network_frames.fetch(:ipv6_esp))[:udp]).to be_nil
    fragment = [17, 0, 9, 123].pack('CCnN') + 'fragment'
    packet = Redhound.dissect(ether(ipv6(fragment, next_header: 44), type: 0x86dd))
    expect(packet['ipv6.fragment.offset']).to eq(8)
    expect(packet['ipv6.fragment.more']).to eq(1)
    expect(packet[:udp]).to be_nil
    short = [17, 3].pack('CC') + "\0" * 6
    expect(codes(Redhound.dissect(ether(ipv6(short, next_header: 0), type: 0x86dd)), :ipv6_ext)).to include(:truncated)
  end

  it 'marks quoted ICMP packets as embedded even when their payload was omitted' do
    inner = ipv4(udp('omitted', dport: 9999)).byteslice(0, 24)
    packet = Redhound.dissect(ether(ipv4([11, 0, 0, 0].pack('CCnN') + inner, proto: 1)))
    expect(packet.layers_of(:ipv4).map(&:embedded)).to eq([false, true])
    expect(codes(packet)).to include(:truncated)
    inner6 = ipv6(udp('x', dport: 9999))
    packet = Redhound.dissect(ether(ipv6([1, 4, 0, 0].pack('CCnN') + inner6, next_header: 58), type: 0x86dd))
    expect(packet.layers_of(:ipv6).map(&:embedded)).to eq([false, true])
    expect(packet.innermost(:udp).embedded).to be(true)
  end

  it 'decodes ICMPv6 echo identifiers, NDP options and harmless unknown NDP options' do
    echo = Redhound.dissect(network_frames.fetch(:icmpv6_echo))
    expect(echo['icmpv6.echo.identifier']).to eq(7)
    expect(echo['icmpv6.echo.sequence_number']).to eq(9)
    expect(Redhound.dissect(network_frames.fetch(:ndp_ns))['icmpv6.opt.linkaddr']).to eq('02:00:00:00:00:01')
    expect(Redhound.dissect(network_frames.fetch(:ndp_ra))['icmpv6.opt.mtu']).to eq(1500)
    ns = [135, 0, 0, 0].pack('CCnN') + ip6('2001:db8::2') + [254, 1, 0, 0].pack('CCnN')
    expect(codes(Redhound.dissect(ether(ipv6(ns, next_header: 58), type: 0x86dd)))).to be_empty
  end

  it 'rejects zero-length NDP options and detects options cut short by capture' do
    ["\1\0", "\1\1\0"].each_with_index do |option, index|
      ns = [135, 0, 0, 0].pack('CCnN') + ip6('2001:db8::2') + option
      packet = Redhound.dissect(ether(ipv6(ns, next_header: 58), type: 0x86dd))
      expect(codes(packet, :icmpv6)).to include(index.zero? ? :bad_length : :truncated)
    end
  end

  it 'detects IGMPv3 source and record counts that exceed the captured message' do
    query = [0x11, 10, 0, 0, 2, 125, 2, 0xc0000201].pack('CCnNCCnN')
    report = [0x22, 0, 0, 0, 1, 1, 0, 2, 0xef010101, 0xc0000201].pack('CCnnnCCnNN')
    [query, report].each do |message|
      expect(codes(Redhound.dissect(ether(ipv4(message, proto: 2))), :igmp)).to include(:truncated)
    end
  end

  it 'decodes TCP options and preserves raw sequence and acknowledgement numbers' do
    packet = Redhound.dissect(network_frames.fetch(:tcp_options))
    expect(packet['tcp.seq']).to eq(0x12345678)
    expect(packet['tcp.ack']).to eq(0x87654321)
    expect(packet['tcp.options.mss_val']).to eq(1460)
    expect(packet['tcp.options.wscale.shift']).to eq(7)
    expect(packet['tcp.options.sack_perm']).to be(true)
    expect(packet['tcp.options.timestamp.tsval']).to eq(123456)
    expect(packet['tcp.options.timestamp.tsecr']).to eq(654321)
    packet = Redhound.dissect(network_frames.fetch(:tcp_sack_tfo))
    expect(packet['tcp.options.sack']).to eq([1000, 2000].pack('N2'))
    expect(packet['tcp.options.tfo.cookie']).to eq('abcd')
  end

  it 'rejects invalid TCP offsets and malformed option lengths without parsing beyond the header' do
    bytes = tcp(''.b, dport: 9999)
    bytes.setbyte(12, 0x40)
    expect(codes(Redhound.dissect(ether(ipv4(bytes, proto: 6))), :tcp)).to include(:bad_length)
    ["\2\0\0\0", "\2\5\0\0", "\1\1\1\2"].each do |options|
      bytes = tcp_options(options, dport: 9999)
      expect(codes(Redhound.dissect(ether(ipv4(bytes, proto: 6))), :tcp)).to include(:bad_length)
    end
    # A valid EOL prevents the following garbage from being interpreted as options.
    bytes = tcp_options("\0\2\0\0", dport: 9999)
    expect(codes(Redhound.dissect(ether(ipv4(bytes, proto: 6))))).to be_empty
  end

  it 'bounds UDP payloads and distinguishes short length fields from short captures' do
    bytes = udp('abcdefgh', dport: 9999)
    bytes[4, 2] = [10].pack('n')
    expect(Redhound.dissect(ether(ipv4(bytes)))['data.data']).to eq('ab')
    bytes[4, 2] = [7].pack('n')
    expect(codes(Redhound.dissect(ether(ipv4(bytes))), :udp)).to include(:bad_length)
    bytes[4, 2] = [100].pack('n')
    expect(codes(Redhound.dissect(ether(ipv4(bytes))), :udp)).to include(:truncated)
  end

  it 'verifies IPv4, IPv6 and odd-length transport checksums and detects corrupted bytes' do
    %i[ipv4_udp ipv6_udp tcp_options icmp_echo icmpv6_echo ndp_ns ndp_ra].each do |name|
      bytes = network_frames.fetch(name)
      expect(codes(checked(bytes))).not_to include(:bad_checksum), name.to_s
      damaged = bytes.dup
      # The final nonpadding byte belongs to the transport message in every selected frame.
      end_offset = Redhound.dissect(bytes).layers.find { |layer| %i[ipv4 ipv6].include?(layer.protocol) }.payload_end - 1
      damaged.setbyte(end_offset, damaged.getbyte(end_offset) ^ 1)
      expect(codes(checked(damaged))).to include(:bad_checksum), name.to_s
    end
  end

  it 'skips checksum verification for transmission offload, incomplete fragments and quoted packets' do
    bytes = network_frames.fetch(:tcp_options)
    expect(codes(checked(bytes, direction: :out))).to include(:checksum_unverified)
    expect(codes(checked(bytes, meta: { csum_not_ready: true }))).to include(:checksum_unverified)
    fragmented = ipv4(tcp('fragment', dport: 9999), proto: 6)
    fragmented[6, 2] = [0x2000].pack('n')
    expect(codes(checked(ether(fragmented)), :tcp)).to include(:checksum_unverified)
    expect(checked(network_frames.fetch(:icmp_error)).innermost(:ipv4).diagnostics.map(&:code)).to include(:checksum_unverified)
    expect(codes(checked(ether(ipv4(udp('x', dport: 9999)))), :udp)).not_to include(:bad_checksum)
    expect(codes(checked(ether(ipv6(udp('x', dport: 9999)), type: 0x86dd)), :udp)).to include(:bad_checksum)
  end

  it 'decodes optional GRE words and Ethernet tunnels and rejects unsupported GRE flags' do
    packet = Redhound.dissect(network_frames.fetch(:gre))
    expect(packet['gre.key']).to eq(42)
    expect(packet.layers_of(:ipv4).length).to eq(2)
    expect(Redhound.dissect(network_frames.fetch(:gre_ethernet)).layers_of(:eth).length).to eq(2)
    [1, 0x4000].each do |flags|
      expect(codes(Redhound.dissect(ether(ipv4([flags, 0x0800].pack('n2') + ipv4(''), proto: 47))), :gre)).to include(:malformed)
    end
    expect(codes(Redhound.dissect(ether(ipv4([0x2000, 0x0800].pack('n2') + "\0", proto: 47), pad: false)), :gre)).to include(:truncated)
  end

  it 'decodes a VXLAN VNI and requires its valid VNI flag' do
    packet = Redhound.dissect(network_frames.fetch(:vxlan))
    expect(packet['vxlan.vni']).to eq(42)
    expect(packet.layers_of(:eth).length).to eq(2)
    bytes = [0, 42 << 8].pack('N2') + ether(ipv4(udp('x', dport: 9999)))
    packet = Redhound.dissect(ether(ipv4(udp(bytes, dport: 4789))))
    expect(codes(packet, :vxlan)).to include(:malformed)
    expect(packet.layers_of(:eth).length).to eq(1)
  end
end
