# frozen_string_literal: true

require 'open3'
require 'tmpdir'
require 'timeout'

RSpec.describe 'command line' do
  it 'validates numeric options and conflicting inputs' do
    expect { Redhound::CLI::Options.new(['-c', '0']) }.to raise_error(Redhound::ConfigurationError)
    expect { Redhound::CLI::Options.new(['-r', 'a', '-i', 'lo']) }.to raise_error(Redhound::ConfigurationError)
    expect { Redhound::CLI::Options.new(['-Q', 'sideways']) }.to raise_error(Redhound::ConfigurationError)
  end
  it 'keeps tcpdump verbosity and timestamps and handles fields -e' do
    opts = Redhound::CLI::Options.new(%w[-vv -tt -T fields -e ip.src -e tcp.dstport -r a tcp port 80]).values
    expect(opts).to include(verbosity: 2, timestamp: :epoch, fields: %w[ip.src tcp.dstport], filter: 'tcp port 80')
  end
  it 'reports usage errors with status 2 and runtime errors with status 1' do
    exe = File.expand_path('../../exe/redhound', __dir__)
    _, err, status = Open3.capture3(RbConfig.ruby, exe, '-c', '0')
    expect(status.exitstatus).to eq(2)
    expect(err).to include('redhound:')
    _, _, status = Open3.capture3(RbConfig.ruby, exe, '-r', '/no/such/redhound.pcap')
    expect(status.exitstatus).to eq(1)
  end
  it 'reads a pcap without privilege and writes packets before any dissection' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'in.pcap')
      bytes = ether(ipv4(udp('x', dport: 9999)))
      File.binwrite(path, [0xa1b2c3d4, 2, 4, 0, 0, 262144, 1].pack('VvvV4') + [1, 0, bytes.bytesize, bytes.bytesize].pack('V4') + bytes)
      exe = File.expand_path('../../exe/redhound', __dir__)
      out, _, status = Open3.capture3(RbConfig.ruby, exe, '-r', path, '-t', '-c', '1')
      expect(status).to be_success
      expect(out).to include('IP 192.0.2.1.12345 > 192.0.2.2.9999: UDP')
    end
  end

  it 'rejects a rotation destination that is also the input without truncating it' do
    Dir.mktmpdir do |dir|
      input = File.join(dir, 'capture_00000.pcap')
      original = File.binread(File.expand_path('../fixtures/pcap/applications.pcap', __dir__))
      File.binwrite(input, original)
      err = StringIO.new
      status = Redhound::CLI::Command.new.run(['-r', input, '-w', File.join(dir, 'capture.pcap'), '-C', '1'], out: StringIO.new, err:)
      expect(status).to eq(2)
      expect(err.string).to include('input and output must be different files')
      expect(File.binread(input)).to eq(original)
    end
  end

  it 'stops on SIGTERM while waiting for more stdin capture data' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'capture.pcap')
      exe = File.expand_path('../../exe/redhound', __dir__)
      input, output, error, child = Open3.popen3(RbConfig.ruby, exe, '-r', '-', '-w', path, '-q')
      input.binmode
      input.write([0xa1b23c4d, 2, 4, 0, 0, 262144, 1].pack('VvvV4'))
      input.flush
      Timeout.timeout(3) { sleep 0.01 until File.exist?(path) }
      Process.kill('TERM', child.pid)
      expect(Timeout.timeout(3) { child.value }).to be_success
      expect(File.binread(path).bytesize).to eq(24)
    ensure
      input&.close
      child&.value
      output&.close
      error&.close
    end
  end

  it 'reports SIGUSR1 statistics while waiting for more stdin capture data' do
    skip 'SIGUSR1 is unavailable' unless Signal.list.key?('USR1')
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'capture.pcap')
      exe = File.expand_path('../../exe/redhound', __dir__)
      input, output, error, child = Open3.popen3(RbConfig.ruby, exe, '-r', '-', '-w', path, '-q')
      input.binmode
      input.write([0xa1b23c4d, 2, 4, 0, 0, 262144, 1].pack('VvvV4'))
      input.flush
      Timeout.timeout(3) { sleep 0.01 until File.exist?(path) }
      Process.kill('USR1', child.pid)
      report = Timeout.timeout(3) do
        loop do
          line = error.gets
          raise 'child exited without a statistics report' unless line
          break line if line.include?('packets captured')
        end
      end
      expect(report).to include('0 packets captured')
      Process.kill('TERM', child.pid)
      expect(Timeout.timeout(3) { child.value }).to be_success
    ensure
      input&.close
      child&.value
      output&.close
      error&.close
    end
  end

  it 'records the CLI capture filter in pcapng interface descriptions' do
    Dir.mktmpdir do |dir|
      input = File.expand_path('../fixtures/pcap/applications.pcap', __dir__)
      output = File.join(dir, 'capture.pcapng')
      status = Redhound::CLI::Command.new.run(['-r', input, '-w', output, 'udp'], out: StringIO.new, err: StringIO.new)
      expect(status).to eq(0)
      Redhound.open(output) { |reader| expect(reader.interfaces.first.filter).to eq('udp') }
    end
  end

  it 'records the current filter when filtering a previously filtered pcapng file' do
    Dir.mktmpdir do |dir|
      input = File.join(dir, 'input.pcapng')
      output = File.join(dir, 'output.pcapng')
      Redhound::Writer.open(input, filter: 'ip') do |writer|
        writer << Redhound::Packet.new(ether(ipv4(udp('x'))))
      end
      status = Redhound::CLI::Command.new.run(['-r', input, '-w', output, 'udp'], out: StringIO.new, err: StringIO.new)
      expect(status).to eq(0)
      Redhound.open(output) { |reader| expect(reader.interfaces.first.filter).to eq('udp') }
    end
  end

  it 'lists interface running and loopback state' do
    interface = Redhound::Capture::Interface.new(name: 'lo0', index: 1, flags: 0x49)
    allow(Redhound::Capture).to receive(:interfaces).and_return([interface])
    out = StringIO.new
    expect(Redhound::CLI::Command.new.run(['-D'], out:, err: StringIO.new)).to eq(0)
    expect(out.string).to eq("1.lo0 [Up, Running, Loopback]\n")
  end

  it 'restores signal handlers even if source shutdown fails' do
    options = Redhound::CLI::Options.new(['-r', 'input', '-w', 'output', '-q']).values
    source = double('source', linktype: 1, stopped?: true)
    writer = double('writer', close: nil)
    allow(source).to receive(:close).and_raise(IOError, 'shutdown failed')
    allow(Redhound).to receive(:open).and_return(source)
    allow(Redhound::Writer).to receive(:open).and_return(writer)
    signals = %w[INT TERM USR1 INFO].select { |signal| Signal.list.key?(signal) }
    previous = signals.to_h { |signal| [signal, Signal.trap(signal, 'IGNORE')] }
    runner = Redhound::CLI::Runner.new(options, out: StringIO.new, err: StringIO.new)
    expect { runner.run }.to raise_error(IOError, 'shutdown failed')
    expect(signals.map { |signal| Signal.trap(signal, 'IGNORE') }).to all(eq('IGNORE'))
  ensure
    previous&.each { |signal, handler| Signal.trap(signal, handler) }
  end
end
