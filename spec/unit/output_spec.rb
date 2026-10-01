# frozen_string_literal: true

require 'stringio'
require 'json'

RSpec.describe 'packet output' do
  let(:packet) { Redhound.dissect(ether(ipv4(udp("hi\e[2J".b, dport: 9999))), timestamp_ns: 1_700_000_000_123_456_789) }
  it 'formats addresses, ports and exact epoch nanoseconds' do
    formatter = Redhound::Output::Summary.new(timestamp: :epoch, precision: :nano)
    expect(formatter.line(packet)).to eq('1700000000.123456789 IP 192.0.2.1.12345 > 192.0.2.2.9999: UDP, length 6')
  end
  it 'prints sanitized fields and payloads in tree and hexdump output' do
    io = StringIO.new
    Redhound::Output::Tree.new.format(packet, io)
    Redhound::Output::Hexdump.new(ascii: true, link_layer: true).format(packet, io)
    expect(io.string).to include('ip.src: 192.0.2.1', 'hi.[2J')
    expect(io.string).not_to include("\e")
  end
  it 'produces a valid JSON array and one complete NDJSON object per packet' do
    io = StringIO.new
    formatter = Redhound::Output::Json.new
    formatter.format(packet, io)
    formatter.format(packet, io)
    formatter.finish(io)
    expect(JSON.parse(io.string).length).to eq(2)
    io = StringIO.new
    Redhound::Output::Json.new(ndjson: true).format(packet, io)
    expect(JSON.parse(io.string)['frame']['time_epoch_ns']).to eq(packet.timestamp_ns)
  end
  it 'prints selected fields without terminal escapes' do
    io = StringIO.new
    Redhound::Output::Fields.new(%w[ip.src udp.dstport]).format(packet, io)
    expect(io.string).to eq("192.0.2.1\t9999\n")
  end

  it 'encodes binary interface metadata as valid UTF-8' do
    interface = Redhound::Capture::Interface.new(name: "bad\xff".b)
    packet = Redhound::Packet.new('', interface: interface)
    expect { JSON.generate(packet.to_h) }.not_to raise_error
  end
end
