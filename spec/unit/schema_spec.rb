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
end
