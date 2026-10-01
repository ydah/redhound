# frozen_string_literal: true

require 'tmpdir'

RSpec.describe 'capture integrity' do
  it 'refuses to overwrite the input through another path' do
    Dir.mktmpdir do |dir|
      input = File.join(dir, 'input.pcap')
      output = File.join(dir, 'alias.pcap')
      File.write(input, 'original')
      File.symlink(input, output)
      expect { Redhound::CLI::Options.new(['-r', input, '-w', output]) }.to raise_error(Redhound::ConfigurationError)
      expect(File.read(input)).to eq('original')
    end
  end
  it 'skips dissection when only writing and preserves original bytes' do
    Dir.mktmpdir do |dir|
      input = File.join(dir, 'input.pcap')
      output = File.join(dir, 'output.pcap')
      packet = Redhound::Packet.new("\x01\x02\x03".b, timestamp_ns: 123_456_789, original_length: 9)
      Redhound::Writer.open(input) { |writer| writer << packet }
      expect_any_instance_of(Redhound::Engine).not_to receive(:dissect)
      expect(Redhound::CLI::Command.new.run(['-r', input, '-w', output, '-q'], out: StringIO.new, err: StringIO.new)).to eq(0)
      Redhound.open(output) { |reader| expect(reader.to_a.first.data).to eq(packet.data) }
      expect(File.stat(output).mode & 0o777).to eq(0o600)
    end
  end
end
