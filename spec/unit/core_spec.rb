# frozen_string_literal: true

RSpec.describe 'packet model and dissection' do
  it 'keeps nanoseconds, capture length and binary data without mutating input' do
    input = +'abc'
    packet = Redhound::Packet.new(input, timestamp_ns: 1_700_000_000_123_456_789, original_length: 8)
    expect(packet.data).to be_frozen
    expect(input).not_to be_frozen
    expect(packet.data.encoding).to eq(Encoding::BINARY)
    expect(packet.time.nsec).to eq(123_456_789)
    expect(packet).to be_truncated
  end

  it 'bounds child cursors and rejects negative ranges' do
    cursor = Redhound::Cursor.new("\x01\x02\x03\x04".b, 1, 3)
    expect(cursor.u16(0)).to eq(0x0203)
    expect { cursor.u16(1) }.to raise_error(Redhound::Cursor::Truncated)
    expect { cursor.sub(0, 2) }.to raise_error(ArgumentError)
    expect(cursor.sub(2, 99).remaining).to eq(1)
  end

  it 'parses ARP without interpreting Ethernet padding as IP' do
    packet = Redhound.dissect(ether(arp, type: 0x0806))
    expect(packet.layers.map(&:protocol)).to eq(%i[eth arp])
    expect(packet['arp.src.proto_ipv4']).to eq('192.0.2.1')
  end

  it 'honors IP and UDP boundaries and options' do
    packet = Redhound.dissect(ether(ipv4(udp('hi', dport: 9999), options: "\x01\x01\x01\x00".b)))
    expect(packet['ip.version']).to eq(4)
    expect(packet['ip.hdr_len']).to eq(24)
    expect(packet[:data][:data]).to eq('hi')
    expect(packet.layers.map(&:protocol)).to eq(%i[eth ipv4 udp data])
  end

  it 'supports custom compiled headers and port registration' do
    plugin = Class.new(Redhound::Dissector) do
      protocol :example, name: 'Example', short: 'EX'
      dissects_on 'udp.port', 9998
      header do
        bits 8 do
          bit :version, 'example.version', 4
          bit :kind, 'example.kind', 4
        end
        uint16 :length, 'example.length'
      end
    end
    packet = Redhound.dissect(ether(ipv4(udp("\x12\x00\x03".b, dport: 9998))))
    expect(packet[:example][:version]).to eq(1)
    expect(packet['example.length']).to eq(3)
    expect(plugin.header_template).to eq('Cn')
  ensure
    Redhound::Registry.default.register('udp.port', 9998, nil)
    Redhound::Registry.default.protocols.delete(:example)
  end

  it 'reports truncation without swallowing unexpected bugs in strict mode' do
    packet = Redhound.dissect("\x01\x02\x03".b)
    expect(packet.layers.first.diagnostics.first.code).to eq(:truncated)
    expect(packet.to_h[:frame][:caplen]).to eq(3)
  end

  it 'isolates plugin errors during protocol dispatch' do
    plugin = Class.new(Redhound::Dissector) do
      protocol :broken_dispatch, name: 'Broken dispatch', short: 'BROKEN'
      dissects_on 'udp.port', 9997
      header { uint8 :value, 'broken.value' }
      def next_dissector(ctx, layer) = raise 'dispatch failed'
    end
    packet = Redhound.dissect(ether(ipv4(udp('ab', dport: 9997))))
    expect(packet[:broken_dispatch].diagnostics.map(&:code)).to include(:dissector_bug)
  ensure
    Redhound::Registry.default.register('udp.port', 9997, nil)
    Redhound::Registry.default.protocols.delete(:broken_dispatch)
  end

  it 'detects HTTP on nonstandard TCP ports' do
    packet = Redhound.dissect(ether(ipv4(tcp("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", dport: 9996), proto: 6)))
    expect(packet['http.host']).to eq('example.com')
  end
end
