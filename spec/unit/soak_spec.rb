# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require_relative '../../bench/soak'

RSpec.describe RedhoundSoak do
  it 'records a bounded private capture and its actual elapsed time and traffic rate' do
    Dir.mktmpdir do |directory|
      destination = File.join(directory, 'capture')
      options = described_class.options(['--interface', 'lo0', '--duration', '0.03', '--sample', '0.01', '--out', destination])
      source = double('source', linktype: 1, stats: Redhound::Capture::Stats.new(captured: 1, received: 1), close: nil)
      packet = Redhound::Packet.new(ether(ipv4(udp('soak'))))
      count = 0
      allow(source).to receive(:next_packet) do |timeout:|
        count += 1
        if count == 1
          packet
        else
          sleep(timeout)
          nil
        end
      end
      allow(Redhound::Capture).to receive(:open).and_return(source)
      allow(described_class).to receive(:validate_file).and_return({ passed: true })
      expect { expect(described_class.run(options)).to eq(true) }.to output(/completed_duration/).to_stdout
      report = JSON.parse(File.read(File.join(destination, 'result.json')))
      expect(report['elapsed']).to be >= 0.03
      expect(report['captured']).to eq(1)
      expect(report['average_pps']).to be_positive
      expect(report['busy_accepted']).to eq(false)
      path = Dir[File.join(destination, '*.pcapng')].fetch(0)
      expect(File.stat(path).mode & 0o777).to eq(0o600)
      Redhound::Reader.open(path) { |reader| expect(reader.to_a.map(&:data)).to eq([packet.data]) }
      expect(File.stat(destination).mode & 0o777).to eq(0o700)
    end
  end

  it 'records a failed initialization without inventing a start or due time' do
    Dir.mktmpdir do |directory|
      destination = File.join(directory, 'capture')
      options = described_class.options(['--interface', 'en0', '--out', destination])
      allow(Redhound::Capture).to receive(:open).and_raise(Redhound::PermissionDenied, 'BPF requires root')
      expect { expect(described_class.run(options)).to eq(false) }.to output(/BPF requires root/).to_stderr
      report = JSON.parse(File.read(File.join(destination, 'result.json')))
      expect(report['error']).to include('BPF requires root')
      configuration = JSON.parse(File.read(File.join(destination, 'configuration.json')))
      expect(configuration).not_to have_key('started_at')
      expect(configuration).not_to have_key('due_at')
      expect(Dir[File.join(destination, '*.pcapng')]).to be_empty
    end
  end
end
