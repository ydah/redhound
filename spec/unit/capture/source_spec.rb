# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Redhound::Capture do
  it 'resolves supported link types and rejects unknown symbolic types' do
    expect(described_class::Linktype.resolve(:ethernet)).to eq(1)
    expect(described_class::Linktype.resolve(:sll2)).to eq(276)
    expect { described_class::Linktype.resolve(:fictional) }.to raise_error(ArgumentError)
  end

  it 'packs Linux sockaddr_ll and SLL2 headers without native extensions' do
    address = Redhound::Capture::Linux::SockaddrLL.new(protocol: 0x0800, index: 9, hatype: 1, pkttype: 4, address: "abcdef")
    decoded = Redhound::Capture::Linux::SockaddrLL.parse(address.to_sockaddr)
    expect(decoded.index).to eq(9)
    expect(decoded.protocol).to eq(0x0800)
    expect(decoded.pkttype).to eq(4)
    header = Redhound::Capture::Linux::Cooked.header(decoded)
    expect(header.bytesize).to eq(20)
    expect(header.unpack('nnNnCCa8')).to eq([0x0800, 0, 9, 1, 4, 6, "abcdef\0\0"])
  end

  it 'uses bounded polling so stop wakes an idle capture' do
    source = described_class::Source.new
    source.stop
    expect(source.stopped?).to eq(true)
  end

  it 'rejects malformed filters even when the capture has no packets' do
    io = StringIO.new
    Redhound::Writer.open(io) { |_writer| }
    io.rewind
    expect { Redhound.open(io, filter: 'udp and') }.to raise_error(Redhound::FilterSyntaxError)
  end

  it 'rejects invalid kernel filter instructions before attaching them' do
    source = Redhound::Capture::Linux::PacketSocket.allocate
    socket = double('socket')
    source.instance_variable_set(:@socket, socket)
    expect(socket).not_to receive(:setsockopt)
    expect { source.attach_filter(double(instructions: [[0x06, 0, 0, -1]])) }.to raise_error(Redhound::FilterError)
  end

  it 'closes resources when statistics fail during shutdown' do
    source = Redhound::Capture::Linux::PacketSocket.allocate
    socket = double('socket', closed?: false)
    source.instance_variable_set(:@socket, socket)
    source.instance_variable_set(:@closed, false)
    allow(source).to receive(:stats).and_raise(IOError, 'statistics failed')
    expect(socket).to receive(:close)
    expect { source.close }.to raise_error(IOError, 'statistics failed')
    expect(source.stopped?).to be(true)
  end

  it 'releases a mapped ring if capture initialization fails after mapping' do
    source = Redhound::Capture::Linux::TPacketV3.allocate
    ring = double('ring')
    socket = double('socket', closed?: false)
    source.instance_variable_set(:@ring, ring)
    source.instance_variable_set(:@socket, socket)
    expect(ring).to receive(:free)
    expect(socket).to receive(:close)
    source.send(:close_resources)
  end

  it 'reads macOS BPF record alignment, truncation and extended direction metadata' do
    source = Redhound::Capture::Bsd::BpfDevice.allocate
    Redhound::Capture::Source.instance_method(:initialize).bind_call(source)
    interface = described_class::Interface.new(name: 'lo0', index: 1, linktype: 0)
    first = [12, 345, 3, 9, 24].pack('I4S') + "\0\x01" + "\0" * 4 + "abc\0"
    second = [13, 456, 3, 3, 24].pack('I4S') + "\0\0" + "\0" * 4 + "def\0"
    { records: first + second, offset: 0, interfaces: [interface], snaplen: 2, linktype: 0,
      extended_header: true, direction: :inout }.each { |key, value| source.instance_variable_set("@#{key}", value) }
    packets = [source.next_packet(timeout: 0), source.next_packet(timeout: 0)]
    expect(packets.map(&:data)).to eq(%w[ab de])
    expect(packets.map(&:original_length)).to eq([9, 3])
    expect(packets.map(&:direction)).to eq(%i[out in])
    expect(packets.first.timestamp_ns).to eq(12_000_345_000)
  end

  it 'restores stripped VLAN tags in ring packets and returns the block to the kernel' do
    experimental = Warning[:experimental]
    Warning[:experimental] = false
    ring = nil
    [8, 14].each do |caplen|
      bytes = "\0".b * 256
      bytes[8, 16] = [1, 1, 48, 256].pack('L4')
      bytes[48, 24] = [0, 5, 7, caplen, 14, 0x51].pack('L6')
      bytes[72, 2] = [80].pack('S')
      bytes[80, 4] = [7].pack('L')
      bytes[84, 2] = [0x88a8].pack('S')
      bytes[96, 20] = Redhound::Capture::Linux::SockaddrLL.new(protocol: 0x0800, index: 2, hatype: 1).to_sockaddr
      bytes[128, 14] = "abcdefABCDEF\x08\0".b
      ring = IO::Buffer.new(256)
      ring.set_string(bytes)
      source = Redhound::Capture::Linux::TPacketV3.allocate
      Redhound::Capture::Source.instance_method(:initialize).bind_call(source)
      interface = described_class::Interface.new(name: 'eth0', index: 2)
      { ring:, current_block: 0, block_size: 256, block_count: 1, pending_count: 0,
        snaplen: caplen == 8 ? 8 : 100, direction: :inout, cooked: false, linktype: 1, interface: }.each do |key, value|
        source.instance_variable_set("@#{key}", value)
      end
      result = source.next_packet(timeout: 0)
      expect(result.data).to eq(caplen == 8 ? 'abcdefAB' : "abcdefABCDEF\x88\xa8\0\x07\x08\0".b)
      expect(result.original_length).to eq(18)
      expect(result.timestamp_ns).to eq(5_000_000_007)
      expect(result.meta[:vlan_tci]).to eq(7)
      expect(ring.get_value(:u32, 8)).to eq(0)
      ring.free
      ring = nil
    end
  ensure
    ring&.free
    Warning[:experimental] = experimental
  end
end
