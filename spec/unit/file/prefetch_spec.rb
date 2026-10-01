# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'

RSpec.describe 'bounded owned-file reads' do
  def capture_file(format = :pcap)
    Tempfile.create(['redhound-prefetch-', ".#{format}"]) do |file|
      yield file
    end
  end

  it 'reduces small owned-file IO calls and preserves records crossing the bounded read window' do
    %i[pcap pcapng].each do |format|
      capture_file(format) do |file|
        random = Random.new(701)
        payloads = 120.times.map { |index| random.bytes(index % 17 == 0 ? 90_001 : 777) }
        Redhound::Writer.open(file, format: format) do |writer|
          payloads.each { |bytes| writer << Redhound::Packet.new(bytes) }
        end
        file.flush
        reader = Redhound.open(file.path)
        opened = reader.instance_variable_get(:@io)
        reads, partial_reads = [], []
        allow(opened).to receive(:read).and_wrap_original { |method, length| reads << length; method.call(length) }
        allow(opened).to receive(:readpartial).and_wrap_original { |method, length| partial_reads << length; method.call(length) }
        expect(reader.map(&:data)).to eq(payloads)
        expect(reads.size).to be < 10
        expect(partial_reads).not_to be_empty
        expect(partial_reads).to all(be <= 65_536)
        reader.close
        expect(opened).to be_closed
      ensure
        reader&.close
      end
    end
  end

  it 'distinguishes clean EOF from truncated headers and payloads in owned files' do
    [0, 1, 15, 18].each do |remaining|
      capture_file do |file|
        header = [0xa1b23c4d, 2, 4, 0, 0, 262144, 1].pack('VvvV4')
        record = [1, 2, 3, 3].pack('V4') + 'abc'
        file.write(header + record + record.byteslice(0, remaining))
        file.flush
        reader = Redhound.open(file.path)
        expect(reader.next_packet.data).to eq('abc')
        if remaining.zero?
          expect(reader.next_packet).to be_nil
        else
          expect { reader.next_packet }.to raise_error(Redhound::FileFormatError, /truncated/)
        end
      ensure
        reader&.close
      end
    end
  end

  it 'preserves caller-owned File positions, seeks and ownership' do
    capture_file do |file|
      Redhound::Writer.open(file) do |writer|
        writer << Redhound::Packet.new('abc')
        writer << Redhound::Packet.new('def')
      end
      file.flush
      file.rewind
      reader = Redhound.open(file)
      expect(file.pos).to eq(24)
      expect(reader.next_packet.data).to eq('abc')
      expect(file.pos).to eq(43)
      file.seek(24)
      expect(reader.next_packet.data).to eq('abc')
      expect(file.pos).to eq(43)
      reader.close
      expect(file).not_to be_closed
    end
  end

  it 'reports truncation safely if an owned file shrinks after prefetching a partial record' do
    capture_file do |file|
      Redhound::Writer.open(file) { |writer| writer << Redhound::Packet.new('x' * 90_001) }
      file.flush
      reader = Redhound.open(file.path)
      File.truncate(file.path, 0)
      expect { reader.next_packet }.to raise_error(Redhound::FileFormatError, /truncated/)
    ensure
      reader&.close
    end
  end

  it 'keeps full CLI stream analysis on owned files' do
    path = File.expand_path('../../fixtures/pcap/analysis-reassembly.pcap', __dir__)
    output = StringIO.new
    status = Redhound::CLI::Command.new.run(['-r', path, '-T', 'fields', '-e', 'http.host', '-e', 'tcp.stream'],
                                           out: output, err: StringIO.new)
    expect(status).to eq(0)
    expect(output.string).to include('example.test')
    expect(output.string).to match(/\t0\n/)
  end
end
