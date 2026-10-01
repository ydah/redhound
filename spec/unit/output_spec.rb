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
    expect(packet.to_h[:frame][:interface]).to eq('626164ff')
  end

  it 'keeps pre-epoch date fractions consistent with the capture instant' do
    packet = Redhound::Packet.new('', timestamp_ns: -1)
    date = Redhound::Output::Timestamp.new(style: :date, precision: :nano).format(packet)
    expect(date).to eq(packet.time.strftime('%Y-%m-%d %H:%M:%S.') + '999999999')
    expect(Redhound::Output::Timestamp.new(style: :epoch, precision: :nano).format(packet)).to eq('-0.000000001')
  end

  it 'pairs tunnel payload ports with their own IP addresses' do
    inner = ipv4(udp('inner', dport: 9999), src: '198.51.100.1', dst: '198.51.100.2')
    packet = Redhound.dissect(ether(ipv4(inner, proto: 4)))
    line = Redhound::Output::Summary.new(timestamp: :none).line(packet)
    expect(line).to include('IP 198.51.100.1.12345 > 198.51.100.2.9999: UDP, length 5')
    expect(line).not_to include('192.0.2.1.12345')
  end

  it 'identifies capture interfaces and directions safely in summary and tree' do
    interface = Redhound::Capture::Interface.new(name: "eth0\e[2J")
    packet = Redhound.dissect(ether(ipv4(udp('x', dport: 9999))), interface: interface, direction: :in)
    line = Redhound::Output::Summary.new(timestamp: :none).line(packet)
    expect(line).to include('eth0\\x1b[2J In')
    tree = StringIO.new
    Redhound::Output::Tree.new.format(packet, tree)
    expect(tree.string).to include('eth0\\x1b[2J In')
    expect(tree.string).not_to include("\e")
  end

  it 'includes checksums and TCP options in verbose summaries' do
    segment = tcp(''.b, dport: 9999)
    segment.setbyte(12, 0x60)
    segment << [2, 4, 1460].pack('CCn')
    packet = Redhound.dissect(ether(ipv4(segment, proto: 6)))
    line = Redhound::Output::Summary.new(timestamp: :none, verbosity: 1).line(packet)
    expect(line).to include('mss_val 1460', 'checksum 0x0', 'ttl 64')
  end
end
