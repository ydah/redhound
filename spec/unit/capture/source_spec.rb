# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

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

  it 'replaces and removes a file source capture filter' do
    io = StringIO.new
    Redhound::Writer.open(io) do |writer|
      writer << Redhound::Packet.new(ether(ipv4(udp('first'))))
      writer << Redhound::Packet.new(ether(ipv4(tcp, proto: 6)))
      writer << Redhound::Packet.new(ether(ipv4(udp('last'))))
    end
    io.rewind
    reader = Redhound.open(io, filter: 'tcp')
    reader.attach_filter(Redhound::Filter.compile('udp'))
    expect(reader.next_packet.data).to include('first')
    reader.attach_filter(nil)
    expect(reader.next_packet['ip.proto']).to eq(6)
    expect(reader.next_packet.data).to include('last')
  end

  it 'stops a file source waiting for stream data without closing the supplied IO' do
    input, output = IO.pipe
    output.write([0xa1b23c4d, 2, 4, 0, 0, 262144, 1].pack('VvvV4'))
    reader = Redhound.open(input)
    thread = Thread.new { reader.next_packet }
    sleep 0.05
    reader.stop
    expect(thread.join(0.5)).not_to be_nil
    expect(thread.value).to be_nil
    expect(input).not_to be_closed
  ensure
    thread&.kill
    thread&.join
    reader&.close
    input&.close
    output&.close
  end

  it 'times out on a partial stream record and resumes without losing bytes' do
    input, output = IO.pipe
    output.write([0xa1b23c4d, 2, 4, 0, 0, 262144, 1].pack('VvvV4'))
    reader = Redhound.open(input)
    record = [1, 2, 3, 3].pack('V4') + 'abc'
    output.write(record.byteslice(0, 8))
    expect(Timeout.timeout(0.3) { reader.next_packet(timeout: 0.02) }).to be_nil
    expect(reader).not_to be_stopped
    output.write(record.byteslice(8..))
    expect(reader.next_packet(timeout: 0.5).data).to eq('abc')
  ensure
    reader&.close
    input&.close
    output&.close
  end

  it 'propagates malformed stream errors to the caller and stops the reader worker' do
    input, output = IO.pipe
    output.write([0xa1b23c4d, 2, 4, 0, 0, 262144, 1].pack('VvvV4'))
    reader = Redhound.open(input)
    output.write([1, 0, 3, 3].pack('V4') + 'ab')
    output.close
    expect { reader.next_packet(timeout: 0.5) }.to raise_error(Redhound::FileFormatError, /truncated/)
    reader.close
    expect(reader.instance_variable_get(:@reader_thread)).not_to be_alive
  ensure
    reader&.close
    input&.close
    output&.close unless output&.closed?
  end

  it 'closes a stream whose bounded reader queue is full' do
    input, output = IO.pipe
    output.write([0xa1b23c4d, 2, 4, 0, 0, 262144, 1].pack('VvvV4'))
    reader = Redhound.open(input)
    output.write(([1, 0, 3, 3].pack('V4') + 'abc') * 10)
    expect(reader.next_packet(timeout: 0.5).data).to eq('abc')
    reader.close
    expect(reader.instance_variable_get(:@reader_thread)).not_to be_alive
    expect(input).not_to be_closed
  ensure
    reader&.close
    input&.close
    output&.close
  end

  it 'warns about socket VLAN offload limits on Ethernet interfaces' do
    source = Redhound::Capture::Linux::PacketSocket.allocate
    source.instance_variable_set(:@interface, described_class::Interface.new(name: 'eth0', index: 2))
    source.instance_variable_set(:@linktype, 1)
    expect { source.send(:warn_vlan_offload) }.to output(/ethtool -K eth0 rxvlan off/).to_stderr
  end

  it 'warns when forcing the requested socket receive buffer needs unavailable privileges' do
    source = Redhound::Capture::Linux::PacketSocket.allocate
    socket = double('socket')
    source.instance_variable_set(:@socket, socket)
    allow(socket).to receive(:setsockopt).with(Socket::SOL_SOCKET, Socket::SO_RCVBUF, [1024].pack('i'))
    allow(socket).to receive(:setsockopt).with(Socket::SOL_SOCKET, Redhound::Capture::Linux::Constants::SO_RCVBUFFORCE, [1024].pack('i')).and_raise(Errno::EPERM)
    expect { source.send(:setup_receive_buffer, 1024) }.to output(/SO_RCVBUFFORCE.*SO_RCVBUF/).to_stderr
  end

  it 'discovers macOS loopback linktype and interface MTU without capture privileges' do
    skip 'macOS interface ioctls' unless RUBY_PLATFORM.include?('darwin')

    interface = described_class::Interface.find('lo0')
    expect(interface.linktype).to eq(0)
    expect(interface.mtu).to be_positive
    out = StringIO.new
    expect(Redhound::CLI::Command.new.run(['-i', 'lo0', '-d', 'ip'], out:, err: StringIO.new)).to eq(0)
    expect(out.string).to include('ld [0]')
    expect(out.string).not_to include('ldh [12]')
  end

  it 'reads macOS AF_LINK address bytes after the variable interface name' do
    socket = double('socket', close: nil)
    allow(Socket).to receive(:new).with(Socket::AF_INET, Socket::SOCK_DGRAM, 0).and_return(socket)
    allow(socket).to receive(:ioctl) { |_command, bytes| bytes[16, 4] = [1500].pack('i'); 0 }
    address = [20, 18, 3, 6, 3, 6, 0].pack('CCSCCCC') + 'en0' + mac('02:00:00:00:00:01')
    interface = Redhound::Capture::Bsd::Ifreq.interface('en0', index: 3, flags: 0x41, link_address: address)
    expect(interface.mac).to eq('02:00:00:00:00:01')
    expect(interface.mtu).to eq(1500)
    expect(interface.linktype).to eq(1)
  end

  it 'honors a socket timeout while readable packets are rejected by direction' do
    source = Redhound::Capture::Linux::PacketSocket.allocate
    Redhound::Capture::Source.instance_method(:initialize).bind_call(source)
    source.instance_variable_set(:@direction, :out)
    address = Redhound::Capture::Linux::SockaddrLL.new(protocol: 0x0800, index: 2, hatype: 1)
    socket = double('socket')
    source.instance_variable_set(:@socket, socket)
    allow(source).to receive(:wait_readable).and_return(true)
    calls = 0
    allow(socket).to receive(:recvfrom_nonblock) do
      calls += 1
      raise 'timeout was ignored' if calls > 5
      ['packet', double(to_sockaddr: address.to_sockaddr)]
    end
    expect(source.next_packet(timeout: 0)).to be_nil
    expect(calls).to eq(1)
  end

  it 'receives ready socket packets without polling the descriptor first' do
    source = Redhound::Capture::Linux::PacketSocket.allocate
    Redhound::Capture::Source.instance_method(:initialize).bind_call(source)
    address = Redhound::Capture::Linux::SockaddrLL.new(protocol: 0x0800, index: 2, hatype: 1)
    socket = double('socket')
    { socket:, interface: described_class::Interface.new(name: 'eth0', index: 2),
      direction: :inout, snaplen: 262144, linktype: 1, cooked: false }.each do |key, value|
      source.instance_variable_set("@#{key}", value)
    end
    expect(source).not_to receive(:wait_readable)
    allow(source).to receive(:timestamp).and_return(123)
    expect(socket).to receive(:recvfrom_nonblock).once.and_return(['packet', double(to_sockaddr: address.to_sockaddr)])
    expect(source.next_packet(timeout: 0).data).to eq('packet')
  end

  it 'rejects invalid kernel filter instructions before attaching them' do
    source = Redhound::Capture::Linux::PacketSocket.allocate
    socket = double('socket')
    source.instance_variable_set(:@socket, socket)
    expect(socket).not_to receive(:setsockopt)
    expect { source.attach_filter(double(instructions: [[0x06, 0, 0, -1]])) }.to raise_error(Redhound::FilterError)
  end

  it 'preserves acceptance while making RET A filters retain socket original lengths' do
    source = Redhound::Capture::Linux::PacketSocket.allocate
    socket = double('socket')
    source.instance_variable_set(:@socket, socket)
    kernel = nil
    allow(socket).to receive(:setsockopt) do |_level, _option, descriptor|
      length = descriptor.unpack1('S')
      bytes = descriptor.unpack1("P#{length * 8}", offset: 8)
      instructions = (0...length).map { |index| bytes.unpack('SCCL', offset: index * 8) }
      kernel = Redhound::Filter::Program.new(instructions)
    end
    source.attach_filter(Redhound::Filter::Program.new([[0x30, 0, 0, 0], [0x15, 1, 0, 1], [6, 0, 0, 0], [0, 0, 0, 40], [0x16, 0, 0, 0]]))
    expect(kernel.evaluate(Redhound::Packet.new("\x01".b))).to eq(262144)
    expect(kernel.evaluate(Redhound::Packet.new("\x00".b))).to eq(0)
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

  it 'explains when Ruby rejects mapping the zero-sized packet socket' do
    source = Redhound::Capture::Linux::TPacketV3.allocate
    socket = double('socket', setsockopt: nil)
    source.instance_variable_set(:@socket, socket)
    source.instance_variable_set(:@snaplen, 262144)
    allow(IO::Buffer).to receive(:map).with(socket, 8 << 20, 0).and_raise(ArgumentError, 'Invalid negative or zero file size!')
    expect { source.send(:setup_receive_buffer, nil) }.to raise_error(Redhound::UnsupportedPlatform, /IO::Buffer\.map.*packet socket.*Invalid negative or zero file size/)
  end

  it 'falls back automatically when Ruby cannot map a packet socket' do
    stub_const('RUBY_PLATFORM', 'x86_64-linux')
    source = double('socket capture')
    allow(described_class::Linux::TPacketV3).to receive(:new).and_raise(Redhound::UnsupportedPlatform, 'IO::Buffer.map cannot map a packet socket')
    expect(described_class::Linux::PacketSocket).to receive(:new).with(interface: 'lo', snaplen: 262144, promiscuous: true, buffer_size: nil, direction: :inout, filter: nil).and_return(source)
    expect { expect(described_class.open(interface: 'lo')).to eq(source) }.to output(/ring backend unavailable.*using socket/).to_stderr
  end

  it 'keeps invalid ring configuration errors visible instead of falling back' do
    stub_const('RUBY_PLATFORM', 'x86_64-linux')
    allow(described_class::Linux::TPacketV3).to receive(:new).and_raise(ArgumentError, 'buffer size must be positive')
    expect(described_class::Linux::PacketSocket).not_to receive(:new)
    expect { described_class.open(interface: 'lo', buffer_size: -1) }.to raise_error(ArgumentError, 'buffer size must be positive')
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
