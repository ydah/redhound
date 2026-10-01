# frozen_string_literal: true

require 'json_schemer'
require 'json'

RSpec.describe 'packet JSON schema' do
  it 'validates normal and malformed packet output' do
    schema_path = File.expand_path('../../docs/json-schema.json', __dir__)
    schema = JSONSchemer.schema(JSON.parse(File.read(schema_path)))
    [Redhound.dissect(ether(ipv4(udp('hi')))), Redhound.dissect("\x01\x02\x03".b)].each do |packet|
      expect(schema.validate(JSON.parse(JSON.generate(packet.to_h))).to_a).to eq([])
    end
  end

  it 'preserves integer timestamps outside four-digit calendar years' do
    schema_path = File.expand_path('../../docs/json-schema.json', __dir__)
    schema = JSONSchemer.schema(JSON.parse(File.read(schema_path)))
    [253_402_300_800_000_000_000, -62_198_755_200_000_000_001].each do |timestamp|
      packet = Redhound::Packet.new('', timestamp_ns: timestamp)
      data = JSON.parse(JSON.generate(packet.to_h))
      expect(data.dig('frame', 'time_epoch_ns')).to eq(timestamp)
      expect(schema.validate(data).to_a).to eq([])
    end
  end

  it 'preserves invalid UTF-8 plugin exception messages as safe hexadecimal' do
    plugin = Class.new(Redhound::Dissector) do
      protocol :binary_error, name: 'Binary error', short: 'BINARY'
      dissects_on 'udp.port', 9995
      def dissect(ctx, layer) = raise(RuntimeError, "bad\xff".b)
    end
    packet = Redhound.dissect(ether(ipv4(udp('x', dport: 9995))))
    diagnostic = packet[:binary_error].diagnostics.first
    expect(diagnostic.code).to eq(:dissector_bug)
    expect { JSON.generate(packet.to_h) }.not_to raise_error
    expect(packet.to_h[:diagnostics].first[:message]).to eq(diagnostic.message.unpack1('H*'))
  ensure
    Redhound::Registry.default.register('udp.port', 9995, nil)
    Redhound::Registry.default.protocols.delete(:binary_error)
  end
end
