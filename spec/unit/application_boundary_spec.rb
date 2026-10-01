# frozen_string_literal: true

require_relative '../fixtures/generators/applications'

RSpec.describe 'application field source ranges' do
  include ApplicationFixtures

  def application_packet(bytes, port:, tcp: false)
    transport = tcp ? self.tcp(bytes, dport: port, flags: 0x18) : udp(bytes, dport: port)
    Redhound.dissect(ether(ipv4(transport, proto: tcp ? 6 : 17)))
  end

  it 'locates each address in concatenated DHCP options after its own TLV header' do
    options = [6, 4].pack('CC') + ip4('192.0.2.53') + [6, 4].pack('CC') + ip4('192.0.2.54') + "\xff".b
    packet = application_packet(dhcp(options), port: 67)
    fields = packet[:dhcp].fields.select { |field| field.name == 'dhcp.option.domain_name_server' }
    expect(fields.map(&:value)).to eq(%w[192.0.2.53 192.0.2.54])
    expect(fields.map { |field| packet.data.byteslice(field.offset, field.length) }).to eq([ip4('192.0.2.53'), ip4('192.0.2.54')])
  end

  it 'spans split DHCP scalar values from the first fragment to the final fragment' do
    bytes = ip4('192.0.2.53')
    options = [6, 2].pack('CC') + bytes.byteslice(0, 2) + [6, 2].pack('CC') + bytes.byteslice(2, 2) + "\xff".b
    packet = application_packet(dhcp(options), port: 67)
    field = packet[:dhcp].fields.find { |item| item.name == 'dhcp.option.domain_name_server' }
    expect(field.value).to eq('192.0.2.53')
    expect(packet.data.byteslice(field.offset, field.length)).to eq(bytes.byteslice(0, 2) + [6, 2].pack('CC') + bytes.byteslice(2, 2))
  end

  it 'locates HTTP header values after optional whitespace' do
    packet = application_packet("GET / HTTP/1.1\r\nHost: \t example.test \t\r\n\r\n", port: 80, tcp: true)
    field = packet[:http].fields.find { |item| item.name == 'http.host' }
    expect(field.value).to eq('example.test')
    expect(packet.data.byteslice(field.offset, field.length)).to eq('example.test')
  end

  it 'trims only boundary HTTP whitespace and preserves long interior tabs and invalid control bytes' do
    interior = 'a' + "\t" * 4096 + 'b'
    [[" \tvalue \t", 'value'], ["\t \t", ''],
     [" \t#{interior}" + "\t" * 4096, interior], ["\tvalue\v\t", "value\v"]].each do |raw, expected|
      packet = application_packet("GET / HTTP/1.1\r\nHost:#{raw}\r\n\r\n", port: 80, tcp: true)
      field = packet[:http].fields.find { |item| item.name == 'http.host' }
      expect(field.value).to eq(expected)
      expect(packet.data.byteslice(field.offset, field.length)).to eq(expected)
      expect(packet[:http].diagnostics.map(&:code)).to include(:malformed) if expected.include?("\v")
    end
  end

  it 'bounds every normal application source range within its packet payload' do
    sample_messages.each_value do |bytes, tcp, port|
      packet = application_packet(bytes, port: port, tcp: tcp)
      packet.layers.each do |layer|
        layer.fields.each do |field|
          next if field.length.zero?
          expect(field.offset).to be >= layer.offset
          expect(field.offset + field.length).to be <= layer.payload_end
        end
      end
    end
    packet = application_packet(ntp + 'extension', port: 123)
    field = packet[:ntp].fields.find { |item| item.name == 'ntp.extension' }
    expect(packet.data.byteslice(field.offset, field.length)).to eq('extension')
    packet = application_packet(tls_record(tls_hello), port: 443, tcp: true)
    field = packet[:tls].fields.find { |item| item.name == 'tls.handshake.extensions_server_name' }
    expect(packet.data.byteslice(field.offset, field.length)).to eq('example.test')
  end

  it 'rejects an empty item in an HTTP Content-Length list' do
    ['', '1,'].each do |value|
      packet = application_packet("POST / HTTP/1.1\r\nContent-Length: #{value}\r\n\r\nx", port: 80, tcp: true)
      expect(packet[:http].diagnostics.map(&:code)).to include(:malformed)
    end
  end

  it 'keeps signed NTP precision correct even when later timestamps are truncated' do
    packet = application_packet(ntp.byteslice(0, 4), port: 123)
    expect(packet['ntp.precision']).to eq(-6)
    expect(packet[:ntp].diagnostics.map(&:code)).to include(:truncated)
  end
end
