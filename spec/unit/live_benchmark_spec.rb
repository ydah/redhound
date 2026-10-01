# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require_relative '../../bench/live_traffic'

RSpec.describe 'live benchmark verification' do
  let(:start_ns) { 1_000_000_000_000_000_000 }
  let(:templates) do
    RedhoundLiveTraffic.decode_templates(RedhoundLiveTraffic.templates(
      source_mac: '02:00:00:00:00:02', destination_mac: '02:00:00:00:00:01', port: 43210, peer_index: 5
    ))
  end

  def packet(sequence, timestamp: start_ns, bytes: nil, length: 600)
    Redhound::Packet.new(bytes || RedhoundLiveTraffic.frame(templates, sequence), timestamp_ns: timestamp, original_length: length)
  end

  it 'rejects corrupted payloads, shifted sequences and zero timestamps that formerly passed' do
    verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 10)
    10.times do |index|
      bytes = templates.fetch('udp').dup
      bytes[42, 8] = [100_000 + index].pack('Q>')
      bytes[56, 544] = 'CORRUPTED'.b.ljust(544, '!')
      verifier.verify(packet(index, bytes: bytes, timestamp: 0))
    end
    expect(verifier.count).to eq(10)
    expect(verifier.gaps).to eq(0)
    expect(verifier.invalid).to be_positive
    expect(verifier.complete?(10)).to eq(false)
  end

  it 'checks all records and accepts only the complete expected mixed sequence' do
    verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, templates: templates)
    10.times { |sequence| verifier.verify(packet(sequence, timestamp: start_ns + sequence * 1_000_000)) }
    expect(verifier.complete?(10)).to eq(true)
    expect(verifier.complete?(11)).to eq(false)
    expect(verifier.protocol_counts).to eq(udp: 5, tcp: 5)
    expect(verifier.report.values_at(:first_sequence, :last_sequence)).to eq([0, 9])
  end

  it 'rejects a corrupt byte in every header and payload region after serialization' do
    [0, 14, 34, 47, 50, 70, 599].each do |offset|
      verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, templates: templates)
      verifier.verify(packet(0))
      bytes = RedhoundLiveTraffic.frame(templates, 1)
      bytes.setbyte(offset, bytes.getbyte(offset) ^ 1)
      verifier.verify(packet(1, bytes: bytes))
      expect(verifier.complete?(2)).to eq(false), "accepted corruption at #{offset}"
    end
  end

  it 'checks every timestamp rather than only the sampled first record' do
    [0, start_ns - 1, start_ns + 2_000_000_001].each do |timestamp|
      verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, templates: templates)
      verifier.verify(packet(0))
      verifier.verify(packet(1, timestamp: timestamp))
      expect(verifier.complete?(2)).to eq(false)
    end
    verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, templates: templates)
    verifier.verify(packet(0, timestamp: start_ns))
    verifier.verify(packet(1, timestamp: start_ns + 2_000_000_000))
    expect(verifier.complete?(2)).to eq(true)
  end

  it 'fails for missing initial or trailing packets, duplicates, reordered frames and truncated records' do
    [[1, 2], [0, 1], [0, 0, 2], [0, 2, 1]].each do |sequence|
      verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, templates: templates)
      sequence.each { |number| verifier.verify(packet(number)) }
      expect(verifier.complete?(3)).to eq(false)
    end
    verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, templates: templates)
    verifier.verify(packet(0, bytes: templates.fetch('udp').byteslice(0, 40)))
    expect(verifier.complete?(1)).to eq(false)
    expect(verifier.complete?(0)).to eq(false)
  end

  it 'validates IPv4-legal zero-checksum UDP payloads and their destination port' do
    verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, port: 43210)
    verifier.verify(packet(0))
    expect(verifier.complete?(1)).to eq(true)
    [56, 599].each do |offset|
      verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, port: 43210)
      bytes = templates.fetch('udp').dup
      bytes.setbyte(offset, 0)
      verifier.verify(packet(0, bytes: bytes))
      expect(verifier.complete?(1)).to eq(false)
    end
    verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, port: 1)
    verifier.verify(packet(0))
    expect(verifier.complete?(1)).to eq(false)
  end

  it 'keeps TCP and IPv4 checksums valid across every counter-word carry' do
    [1, 0xffff, 0x1_0001, 0xffff_ffff, 0x1_0000_0001, 0x1_0000_0000_0001, 0xffff_ffff_ffff_ffff].each do |sequence|
      bytes = RedhoundLiveTraffic.frame(templates, sequence)
      expect(bytes.bytesize).to eq(600)
      expect(bytes.unpack1('Q>', offset: 54)).to eq(sequence)
      expect(checksum(bytes.byteslice(14, 20))).to eq(0)
      tcp = bytes.byteslice(34..)
      pseudo = bytes.byteslice(26, 8) + [0, 6, tcp.bytesize].pack('CCn')
      expect(checksum(pseudo + tcp)).to eq(0), "counter #{sequence} produced an invalid TCP checksum"
    end
  end

  it 'verifies serialized records and rejects payload, timestamp and original-length changes' do
    Dir.mktmpdir do |directory|
      [:valid, :payload, :timestamp, :original_length].each do |change|
        path = File.join(directory, "#{change}.pcap")
        bytes = RedhoundLiveTraffic.frame(templates, 1)
        bytes.setbyte(599, 0) if change == :payload
        last = packet(1, bytes: bytes, timestamp: change == :timestamp ? 0 : start_ns,
                      length: change == :original_length ? 601 : 600)
        Redhound::Writer.open(path) { |writer| writer.write(packet(0)); writer.write(last) }
        verifier = RedhoundLiveTraffic::Verifier.new(start_ns: start_ns, duration: 1, templates: templates)
        Redhound::Reader.open(path) { |reader| reader.each { |record| verifier.verify(record) } }
        expect(verifier.complete?(2)).to eq(change == :valid)
      end
    end
  end
end
