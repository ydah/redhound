# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'stringio'

RSpec.describe 'capture file formats' do
  def packet(data = 'packet', **options)
    Redhound::Packet.new(data.b, timestamp_ns: 1_700_000_000_123_456_789, original_length: 64, **options)
  end

  def pcap(endian, nano)
    magic = nano ? 0xa1b23c4d : 0xa1b2c3d4
    format = endian == :little ? 'VvvVVVV' : 'NnnNNNN'
    record = endian == :little ? 'V4' : 'N4'
    fraction = nano ? 123_456_789 : 123_456
    [magic, 2, 4, 0, 0, 100, 1 | (3 << 28)].pack(format) +
      [1_700_000_000, fraction, 3, 64].pack(record) + 'abc'
  end

  it 'reads all four pcap magic values and ignores upper linktype bits' do
    %i[little big].product([true, false]).each do |endian, nano|
      reader = Redhound::Reader.new(StringIO.new(pcap(endian, nano)))
      result = reader.to_a.fetch(0)
      expect(result.data).to eq('abc')
      expect(result.original_length).to eq(64)
      expect(result.linktype).to eq(1)
      expect(result.timestamp_ns).to eq(nano ? 1_700_000_000_123_456_789 : 1_700_000_000_123_456_000)
    end
  end

  it 'rejects truncated and oversized records before allocating payloads' do
    expect { Redhound::Reader.new(StringIO.new(pcap(:little, true)[0...-1])).to_a }.to raise_error(Redhound::FileFormatError)
    bytes = pcap(:little, true)
    bytes[32, 4] = [17 * 1024 * 1024].pack('V')
    expect { Redhound::Reader.new(StringIO.new(bytes)).to_a }.to raise_error(Redhound::FileFormatError)
  end

  it 'normalizes foreign-endian NULL headers before applying capture filters' do
    %i[little big].each do |endian|
      word = endian == :little ? 'V' : 'N'
      header_format = endian == :little ? 'VvvV4' : 'NnnN4'
      data = [2].pack(word) + ipv4(udp('x'.b, dport: 9999))
      capture = [0xa1b23c4d, 2, 4, 0, 0, 262144, 0].pack(header_format) +
                [1, 0, data.bytesize, data.bytesize].pack("#{word}4") + data
      reader = Redhound::Reader.new(StringIO.new(capture), filter: 'ip and udp port 9999')
      result = reader.to_a
      expect(result.size).to eq(1)
      expect(result.first.data.byteslice(0, 4)).to eq([2].pack('L'))

      short = endian == :little ? 'v' : 'n'
      block = ->(type, body) { [type, body.bytesize + 12].pack("#{word}2") + body + [body.bytesize + 12].pack(word) }
      capture = block.call(0x0a0d0d0a, [0x1a2b3c4d, 1, 0, -1].pack(endian == :little ? 'Vvvq<' : 'Nnnq>')) +
                block.call(1, [0, 0, 262144].pack("#{short}2#{word}")) +
                block.call(6, [0, 0, 1, data.bytesize, data.bytesize].pack("#{word}5") + Redhound::File::Format.pad(data))
      reader = Redhound::Reader.new(StringIO.new(capture), filter: 'ip and udp port 9999')
      result = reader.to_a
      expect(result.size).to eq(1)
      expect(result.first.data.byteslice(0, 4)).to eq([2].pack('L'))
    end
  end

  it 'protects input files from all rotation destinations including aliases' do
    Dir.mktmpdir do |dir|
      base = File.join(dir, 'capture.pcap')
      first = File.join(dir, 'capture_00000.pcap')
      input = File.join(dir, 'original.pcap')
      original = pcap(:little, true)
      File.binwrite(input, original)
      File.link(input, first)
      expect { Redhound::Writer.open(base, max_bytes: 40, forbidden_input: input) }.to raise_error(Redhound::ConfigurationError)
      expect(File.binread(input)).to eq(original)

      base = File.join(dir, 'later.pcap')
      second = File.join(dir, 'later_00001.pcap')
      File.symlink(input, second)
      writer = Redhound::Writer.open(base, max_bytes: 40, forbidden_input: input)
      writer << packet
      expect { writer << packet }.to raise_error(Redhound::ConfigurationError)
      expect(File.binread(input)).to eq(original)
      writer.close
    end
  end

  it 'writes pcap at microsecond and nanosecond precision with private permissions' do
    Dir.mktmpdir do |dir|
      %i[micro nano].each do |precision|
        path = File.join(dir, "#{precision}.pcap")
        Redhound::Writer.open(path, snaplen: 3, precision:) { |writer| writer << packet }
        result = Redhound::Reader.open(path, &:to_a).fetch(0)
        expect(result.data).to eq('pac')
        expect(result.original_length).to eq(64)
        expect(result.timestamp_ns).to eq(precision == :nano ? 1_700_000_000_123_456_789 : 1_700_000_000_123_456_000)
        expect(File.stat(path).mode & 0o777).to eq(0o600)
      end
    end
  end

  it 'round trips multiple pcapng interfaces, comments, flags and statistics' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'capture.pcapng')
      first = Redhound::Capture::Interface.new(name: 'eth0', index: 2, linktype: 1, filter: 'udp')
      second = Redhound::Capture::Interface.new(name: 'tun0', index: 3, linktype: 101)
      Redhound::Writer.open(path) do |writer|
        writer << packet(interface: first, direction: :in, meta: {pkttype: 1, comment: 'hello'})
        writer << packet('ip', interface: second, linktype: 101, direction: :out)
        writer.write_stats(Redhound::Capture::Stats.new(received: 9, dropped: 2, if_dropped: 1))
      end
      reader = Redhound::Reader.new(path)
      results = reader.to_a
      expect(results.map(&:linktype)).to eq([1, 101])
      expect(results.map { |item| item.interface.name }).to eq(%w[eth0 tun0])
      expect(results.map(&:direction)).to eq(%i[in out])
      expect(results.first.meta[:comment]).to eq('hello')
      expect(reader.interfaces.first.filter).to eq('udp')
      expect(reader.stats.received).to eq(9)
      expect(reader.stats.dropped).to eq(2)
      reader.close
    end
  end

  it 'rotates a bounded size ring without invoking a shell' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'with space.pcap')
      writer = Redhound::Writer.open(path, max_bytes: 45, file_count: 2)
      5.times { writer << packet }
      writer.close
      paths = Dir[File.join(dir, '*.pcap')]
      expect(paths.size).to eq(2)
      expect(paths.map { |item| Redhound::Reader.open(item, &:to_a).size }).to eq([1, 1])
    end
  end

  it 'reads independent little and big endian pcapng sections with binary time resolution and SPB' do
    capture = ''.b
    %i[little big].each do |endian|
      word = endian == :little ? 'V' : 'N'
      short = endian == :little ? 'v' : 'n'
      option = ->(code, data) { [code, data.bytesize].pack("#{short}2") + data + "\0" * ((-data.bytesize) & 3) }
      block = ->(type, body) { [type, body.bytesize + 12].pack("#{word}2") + body + [body.bytesize + 12].pack(word) }
      capture << block.call(0x0a0d0d0a, [0x1a2b3c4d, 1, 0, -1].pack(endian == :little ? 'Vvvq<' : 'Nnnq>'))
      options = option.call(2, endian.to_s) + option.call(9, "\x8a".b) + option.call(14, [3].pack(endian == :little ? 'q<' : 'q>')) + "\0" * 4
      capture << block.call(1, [101, 0, 10].pack("#{short}2#{word}") + options)
      capture << block.call(1234, 'skip')
      capture << block.call(6, [0, 0, 1024, 3, 9].pack("#{word}5") + "abc\0")
      capture << block.call(3, [2].pack(word) + "ip\0\0")
    end
    reader = Redhound::Reader.new(StringIO.new(capture))
    expect(reader.linktype).to eq(101)
    expect(reader.interfaces.map(&:name)).to eq(['little'])
    results = reader.to_a
    expect(results.map(&:data)).to eq(%w[abc ip abc ip])
    expect(results.map(&:timestamp_ns)).to eq([4_000_000_000, 0, 4_000_000_000, 0])
    expect(reader.interfaces.map(&:name)).to eq(%w[little big])
  end

  it 'reports file packet counts even without pcapng interface statistics' do
    io = StringIO.new
    writer = Redhound::Writer.open(io, format: :pcapng)
    writer << packet
    writer.close
    reader = Redhound::Reader.new(StringIO.new(io.string))
    expect(reader.to_a.size).to eq(1)
    expect(reader.stats.received).to eq(1)
    expect(reader.stats.captured).to eq(1)
  end

  it 'rejects corrupt pcapng block trailers and packet interface IDs' do
    io = StringIO.new
    writer = Redhound::Writer.open(io, format: :pcapng)
    writer << packet
    writer.close
    bytes = io.string.dup
    bytes[bytes.unpack1('V', offset: 4) - 4, 4] = [12].pack('V')
    expect { Redhound::Reader.new(StringIO.new(bytes)) }.to raise_error(Redhound::FileFormatError)
    bytes = io.string.dup
    offset = 0
    loop do
      type, length = bytes.unpack('V2', offset:)
      if type == 6
        bytes[offset + 8, 4] = [99].pack('V')
        break
      end
      offset += length
    end
    expect { Redhound::Reader.new(StringIO.new(bytes)).to_a }.to raise_error(Redhound::FileFormatError)
  end

  it 'passes a closed filename and command arguments literally to the rotation hook' do
    Dir.mktmpdir do |dir|
      script = File.join(dir, 'rotate.rb')
      output = File.join(dir, 'arguments')
      File.write(script, 'File.write(ARGV.shift, ARGV.join("\\n"))')
      command = [RbConfig.ruby, script, output, 'literal;echo'].map { |word| Shellwords.escape(word) }.join(' ')
      writer = Redhound::Writer.open(File.join(dir, 'with space.pcap'), max_bytes: 40, post_rotate_command: command)
      writer << packet
      writer.close
      expect(File.read(output)).to include("literal;echo\n", 'with space_00000.pcap')
    end
  end
end
