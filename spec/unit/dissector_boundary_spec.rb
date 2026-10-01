# frozen_string_literal: true

RSpec.describe 'readable fields in truncated headers' do
  it 'keeps only complete fixed fields inside the bounded cursor' do
    klass = Class.new(Redhound::Dissector) do
      protocol :bounded_header, name: 'Bounded header', short: 'BOUND'
      header do
        uint16 :first, 'bounded.first'
        uint16 :second, 'bounded.second'
        uint32 :last, 'bounded.last'
      end
    end
    packet = Redhound::Packet.new([1, 2, 3].pack('nnN'))
    ctx = Redhound::Context.new(packet, registry: Redhound::Registry.default)
    ctx.cursor = Redhound::Cursor.new(packet.data, 0, 3)

    layer = Redhound::Engine.new.safely(klass, ctx, ctx.cursor)
    expect(layer.field_value('bounded.first')).to eq(1)
    expect(layer.field_value('bounded.second')).to be_nil
    expect(layer.field_value('bounded.last')).to be_nil
    expect(layer.diagnostics.map(&:code)).to eq([:truncated])
    expect(layer.fields.map { |field| field.offset + field.length }).to all(be <= 3)
  ensure
    Redhound::Registry.default.protocols.delete(:bounded_header)
  end

  it 'retains IPv4 fields when its options are cut off' do
    bytes = ipv4(''.b, options: "\x01\x01\x01\x00".b).byteslice(0, 21)
    packet = Redhound.dissect(bytes, linktype: :raw)
    expect(packet['ip.src']).to eq('192.0.2.1')
    expect(packet['ip.hdr_len']).to eq(24)
    expect(packet[:ipv4].diagnostics.map(&:code)).to include(:truncated)
    expect(packet.layers.map(&:protocol)).to eq(%i[raw ipv4])
  end

  it 'retains TCP ports and sequence when its options exceed the captured IP payload' do
    segment = tcp(''.b, dport: 9999, seq: 123)
    segment[12] = "\x70"
    packet = Redhound.dissect(ether(ipv4(segment, proto: 6)))
    expect(packet['tcp.dstport']).to eq(9999)
    expect(packet['tcp.seq']).to eq(123)
    expect(packet[:tcp].diagnostics.map(&:code)).to include(:truncated)
    expect(packet.layers.map(&:protocol)).to eq(%i[eth ipv4 tcp])
  end

  it 'retains ARP operation and address sizes when an address is missing' do
    packet = Redhound.dissect(ether(arp.byteslice(0, 10), type: 0x0806, pad: false))
    expect(packet['arp.opcode']).to eq(1)
    expect(packet['arp.hw.size']).to eq(6)
    expect(packet[:arp].diagnostics.map(&:code)).to include(:truncated)
  end

  it 'reports the capture receive limit without stopping valid dissection' do
    packet = Redhound.dissect(ether(ipv4(udp('payload', dport: 9999))), meta: { possible_truncation: true })
    diagnostic = packet.layers.first.diagnostics.find { |item| item.code == :capture_truncated }
    expect(diagnostic&.severity).to eq(:warn)
    expect(packet['udp.dstport']).to eq(9999)
    expect(packet.summary).to include('[capture_truncated]')
    expect(packet.to_h[:diagnostics]).to include(hash_including(code: :capture_truncated))
  end

  it 'retains complete IPv4 and TCP fixed fields while omitting partial fields' do
    packet = Redhound.dissect(ipv4(''.b).byteslice(0, 16), linktype: :raw)
    expect(packet['ip.src']).to eq('192.0.2.1')
    expect(packet['ip.dst']).to be_nil
    expect(packet['ip.len']).to eq(20)
    expect(packet[:ipv4].length).to eq(16)
    packet = Redhound.dissect(ether(ipv4(tcp(''.b, seq: 123).byteslice(0, 8), proto: 6)))
    expect(packet['tcp.srcport']).to eq(40000)
    expect(packet['tcp.seq']).to eq(123)
    expect(packet['tcp.ack']).to be_nil
    expect(packet[:tcp].length).to eq(8)
  end
end
