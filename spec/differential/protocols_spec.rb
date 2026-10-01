# frozen_string_literal: true

require 'json'
require 'open3'
require 'tmpdir'
require 'yaml'
require 'time'
require_relative '../fixtures/generators/applications'

RSpec.describe 'protocol fields compared with tshark', :differential do
  include ApplicationFixtures

  def collect(node, name)
    case node
    when Hash
      node.flat_map { |key, value| key == name ? Array(value) : collect(value, name) }
    when Array then node.flat_map { |value| collect(value, name) }
    else []
    end
  end

  def normalized(values, type)
    values.map do |value|
      case type
      when 'int', 'hex' then value.is_a?(Integer) ? value : Integer(value, value.start_with?('0x') ? 16 : 10)
      when 'bool' then value == true || value == '1' || value == 'True'
      when 'ntp_timestamp'
        value.is_a?(Integer) ? Time.at((value >> 32) - 2_208_988_800, (value & 0xffffffff) * 1_000_000_000 / (1 << 32), :nsec).utc : Time.parse(value).utc
      else value.to_s
      end
    end
  end

  it 'matches link, IP, transport and every supported application family' do
    skip 'tshark is not installed' unless system('tshark', '--version', out: File::NULL, err: File::NULL)
    messages = sample_messages.values
    packets = messages.each_with_index.map do |(bytes, tcp, port), i|
      transport = tcp ? self.tcp(bytes, dport: port, flags: 0x18, seq: 1, sport: 40_000 + i) : udp(bytes, dport: port, sport: 40_000 + i)
      Redhound::Packet.new(ether(ipv4(transport, proto: tcp ? 6 : 17)), timestamp_ns: 1_700_000_000_000_000_000 + i * 1_000_000, number: i + 1)
    end
    Dir.mktmpdir('redhound-protocols') do |dir|
      path = File.join(dir, 'applications.pcap')
      writer = Redhound::File::PcapWriter.new(path)
      packets.each { |packet| writer.write(packet) }
      writer.close
      json, error, status = Open3.capture3('tshark', '-n', '-r', path, '-T', 'json', '--no-duplicate-keys')
      expect(status.success?).to be(true), error
      reference = JSON.parse(json)
      expect(reference.length).to eq(packets.length)
      mapping = YAML.safe_load_file(File.join(__dir__, 'field_map.yml'))
      packets.zip(reference).each do |packet, node|
        mapping.each do |field|
          expected = collect(node.dig('_source', 'layers'), field.fetch('reference', field.fetch('name')))
          actual = packet.field_values(field.fetch('name'))
          next if expected.empty? && actual.empty?
          expect(normalized(actual, field.fetch('normalize'))).to eq(normalized(expected, field.fetch('normalize'))),
            "frame #{packet.number}, #{field.fetch('name')}: #{actual.inspect} != #{expected.inspect}"
        end
      end
    end
  end
end
