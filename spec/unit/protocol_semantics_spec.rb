# frozen_string_literal: true

require_relative '../fixtures/generators/network'

RSpec.describe 'protocol wire semantics' do
  include NetworkFixtures

  it 'does not invent echo identifiers from ICMP error-specific bytes' do
    message = [3, 4, 0, 0, 1500].pack('CCnnn') + ipv4(udp('quoted', dport: 9999))
    packet = Redhound.dissect(ether(ipv4(message, proto: 1)))
    expect(packet['icmp.ident']).to be_nil
    expect(packet['icmp.seq']).to be_nil
    expect(packet['icmp.mtu']).to eq(1500)
    expect(packet.layers_of(:ipv4).map(&:embedded)).to eq([false, true])
    expect(packet.summary).not_to include('id 0, seq 1500')
  end

  it 'points variable network fields at the bytes they describe' do
    examples = {
      tcp_options: { 'tcp.options.mss_val' => [22, [1460].pack('n')], 'tcp.options.wscale.shift' => [27, "\x07"],
                     'tcp.options.timestamp.tsval' => [32, [123456].pack('N')] },
      tcp_sack_tfo: { 'tcp.options.sack' => [22, [1000, 2000].pack('N2')], 'tcp.options.tfo.cookie' => [32, 'abcd'] },
      ndp_ns: { 'icmpv6.nd.ns.target_address' => [8, ip6('2001:db8::2')], 'icmpv6.opt.linkaddr' => [26, mac('02:00:00:00:00:01')] },
      ndp_ra: { 'icmpv6.nd.ra.router_lifetime' => [6, [1800].pack('n')], 'icmpv6.opt.prefix' => [32, ip6('2001:db8::')] },
      ndp_redirect: { 'icmpv6.rd.na.destination_address' => [24, ip6('2001:db8::2')] },
      igmp_v3_query: { 'igmp.maddr' => [4, ip4('239.1.1.1')], 'igmp.saddr' => [12, ip4('192.0.2.1')] },
      igmp_v3_report: { 'igmp.record_type' => [8, "\x01"], 'igmp.maddr' => [12, ip4('239.1.1.1')], 'igmp.saddr' => [16, ip4('192.0.2.1')] },
      gre: { 'gre.key' => [8, [42].pack('N')] },
      vxlan: { 'vxlan.vni' => [4, [42 << 8].pack('N').byteslice(0, 3)] }
    }
    aggregate_failures do
      examples.each do |frame, fields|
        packet = Redhound.dissect(network_frames.fetch(frame))
        fields.each do |name, (relative, expected)|
          layer = packet.layers.find { |item| item.field_value(name) }
          field = layer.fields.find { |item| item.name == name }
          expect(field.offset).to eq(layer.offset + relative), name
          expect(field.length).to eq(expected.bytesize), name
          expect(packet.data.byteslice(field.offset, field.length)).to eq(expected.b), name
        end
      end
    end
  end

  it 'rejects malformed known TCP option sizes instead of silently decoding them' do
    ["\x02\x03\x05\0", "\x03\x02\0\0", "\x04\x03\0\0", "\x05\x03\xff\0", "\x08\x04\0\0", "\x22\x03\xff\0"].each do |options|
      packet = Redhound.dissect(ether(ipv4(tcp_options(options.b, dport: 9999), proto: 6)))
      expect(packet[:tcp].diagnostics.map(&:code)).to include(:bad_length), options.unpack1('H*')
      expect(packet[:data]).to be_nil
    end
  end

  it 'terminates IPv6 No Next Header before interpreting trailing bytes' do
    packet = Redhound.dissect(ether(ipv6('ignored', next_header: 59), type: 0x86dd))
    expect(packet.layers.map(&:protocol)).to eq(%i[eth ipv6])
    extension = [59, 0].pack('CC') + "\0" * 6
    packet = Redhound.dissect(ether(ipv6(extension + 'ignored', next_header: 0), type: 0x86dd))
    expect(packet.layers.map(&:protocol)).to eq(%i[eth ipv6 ipv6_ext])
  end

  it 'applies the IPv6 extension limit separately to each encapsulated IP header' do
    inner_extensions = ([0, 0].pack('CC') + "\0" * 6) * 15 + [17, 0].pack('CC') + "\0" * 6
    inner = ipv6(inner_extensions + udp('inner', dport: 9999), next_header: 0)
    outer_extension = [41, 0].pack('CC') + "\0" * 6
    packet = Redhound.dissect(ether(ipv6(outer_extension + inner, next_header: 0), type: 0x86dd))
    expect(packet['udp.dstport']).to eq(9999)
    expect(packet.layers_of(:ipv6_ext).length).to eq(17)
    expect(packet.layers.flat_map(&:diagnostics)).to be_empty
  end

  it 'uses the AH length formula when dispatched from IPv4' do
    ah = [17, 1].pack('CC') + "\0" * 10
    packet = Redhound.dissect(ether(ipv4(ah + udp('inner', dport: 9999), proto: 51)))
    expect(packet['udp.dstport']).to eq(9999)
    expect(packet[:ipv6_ext].header_length).to eq(12)
    expect(packet['ipv6.extension.type']).to eq(51)
  end
end
