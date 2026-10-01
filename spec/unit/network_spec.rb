# frozen_string_literal: true

RSpec.describe 'network protocols' do
  it 'decodes stacked VLAN headers' do
    payload = [100, 0x88a8, 200, 0x0800].pack('n4') + ipv4(udp('hi', dport: 9999))
    packet = Redhound.dissect(ether(payload, type: 0x8100))
    expect(packet.layers_of(:vlan).map { |l| l[:id] }).to eq([100, 200])
    expect(packet['udp.dstport']).to eq(9999)
  end

  it 'keeps both control octets of LLC I and S frames out of the payload' do
    [0, 1].each do |control|
      payload = [0x42, 0x42, control, 1].pack('C4') + 'payload'
      packet = Redhound.dissect(ether(payload, type: payload.bytesize))
      expect(packet[:llc].header_length).to eq(4)
      expect(packet['llc.control']).to eq(0x100 | control)
      expect(packet[:llc].fields.find { |field| field.name == 'llc.control' }.length).to eq(2)
      expect(packet[:data].field_value('data.data')).to eq('payload')
    end
    packet = Redhound.dissect(ether("\x42\x42\0".b, type: 3, pad: false))
    expect(packet[:llc].diagnostics.map(&:code)).to include(:truncated)
  end

  it 'decodes IPv6 extensions and distinguishes noninitial fragments' do
    extension = [17, 0].pack('CC') + "\0" * 6
    packet = Redhound.dissect(ether(ipv6(extension + udp('x', dport: 9999), next_header: 0), type: 0x86dd))
    expect(packet['udp.dstport']).to eq(9999)
    fragment = [17, 0, 9, 123].pack('CCnN') + 'fragment'
    packet = Redhound.dissect(ether(ipv6(fragment, next_header: 44), type: 0x86dd))
    expect(packet['ipv6.fragment.offset']).to eq(8)
    expect(packet[:udp]).to be_nil
  end

  it 'checks IPv4 checksums when requested and ignores offloaded packets' do
    bytes = ether(ipv4(udp('x', dport: 9999)))
    bytes.setbyte(24, 0)
    engine = Redhound::Engine.new(verify_checksums: true)
    packet = Redhound::Packet.new(bytes)
    packet.engine = engine
    expect(packet[:ipv4].diagnostics.map(&:code)).to include(:bad_checksum)
    packet = Redhound::Packet.new(bytes, direction: :out)
    packet.engine = engine
    expect(packet[:ipv4].diagnostics.map(&:code)).to include(:checksum_unverified)
  end

  it 'parses TCP flags and options without reading invalid option lengths' do
    segment = tcp('GET /', flags: 0x18, ack: 1234)
    segment.setbyte(12, 0x60)
    segment[20, 0] = [2, 4, 1460].pack('CCn')
    packet = Redhound.dissect(ether(ipv4(segment, proto: 6)))
    expect(packet['tcp.options.mss_val']).to eq(1460)
    expect(packet['tcp.flags.ack']).to eq(true)
    expect(packet['tcp.hdr_len']).to eq(24)
    expect(packet['tcp.ack']).to eq(1234)
  end

  it 'marks embedded ICMP packets so they do not become separate flows' do
    inner = ipv4(udp('x', dport: 9999))
    packet = Redhound.dissect(ether(ipv4([3, 3, 0, 0].pack('CCnN') + inner, proto: 1)))
    expect(packet.layers_of(:ipv4).map(&:embedded)).to eq([false, true])
  end

  it 'decodes cooked, null and raw captures' do
    bytes = ipv4(udp('x', dport: 9999))
    cooked = [0x0800, 3, 1, 0, 6].pack('nxxNnCC') + mac('02:00:00:00:00:01') + "\0\0" + bytes
    expect(Redhound.dissect(cooked, linktype: 276)['sll.ifindex']).to eq(3)
    expect(Redhound.dissect([2].pack('L') + bytes, linktype: 0)['ip.src']).to eq('192.0.2.1')
    expect(Redhound.dissect(bytes, linktype: 101)['ip.src']).to eq('192.0.2.1')
  end

  it 'parses IGMPv3 query sources and membership records' do
    query = [0x11, 10, 0, 0xef010101, 2, 125, 1, 0xc0000201].pack('CCnNCCnN')
    packet = Redhound.dissect(ether(ipv4(query, proto: 2)))
    expect(packet['igmp.version']).to eq(3)
    expect(packet['igmp.saddr']).to eq('192.0.2.1')
    report = [0x22, 0, 0, 0, 1, 1, 0, 1, 0xef010101, 0xc0000201].pack('CCnnnCCnNN')
    packet = Redhound.dissect(ether(ipv4(report, proto: 2)))
    expect(packet['igmp.record_type']).to eq(1)
    expect(packet['igmp.maddr']).to eq('239.1.1.1')
  end

  it 'parses NDP advertisement flags, redirect destinations and prefix information' do
    prefix = [3, 4, 64, 0xc0, 3600, 1800, 0].pack('C4N3') + ip6('2001:db8::')
    ra = [134, 0, 0, 64, 0xc0, 1800, 1000, 2000].pack('CCnCCnNN') + prefix
    packet = Redhound.dissect(ether(ipv6(ra, next_header: 58), type: 0x86dd))
    expect(packet['icmpv6.nd.ra.flag.m']).to eq(true)
    expect(packet['icmpv6.opt.prefix']).to eq('2001:db8::')
    na = [136, 0, 0, 0xe0000000].pack('CCnN') + ip6('2001:db8::1')
    packet = Redhound.dissect(ether(ipv6(na, next_header: 58), type: 0x86dd))
    expect(packet['icmpv6.nd.na.flag.s']).to eq(true)
    redirect = [137, 0, 0, 0].pack('CCnN') + ip6('2001:db8::1') + ip6('2001:db8::2')
    packet = Redhound.dissect(ether(ipv6(redirect, next_header: 58), type: 0x86dd))
    expect(packet['icmpv6.rd.na.destination_address']).to eq('2001:db8::2')
  end
end
