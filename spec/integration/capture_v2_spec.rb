# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'stringio'

RSpec.describe 'v2 live capture', :live do
  let(:loopback) { RUBY_PLATFORM.include?('darwin') ? 'lo0' : 'lo' }

  def with_udp
    receiver = UDPSocket.new
    sender = UDPSocket.new
    receiver.bind('127.0.0.1', 0)
    yield sender, receiver.addr[1]
  ensure
    sender&.close
    receiver&.close
  end

  (RUBY_PLATFORM.include?('linux') ? %i[socket auto ring] : [:bpf]).each do |backend|
    it "captures filtered UDP with kernel time, original length and bounded snaplen via #{backend}" do
      with_udp do |sender, port|
        begin
          source = Redhound::Capture.open(interface: loopback, backend:, snaplen: 36, promiscuous: false,
                                          filter: "udp dst port #{port}")
        rescue Redhound::UnsupportedPlatform => error
          raise unless backend == :ring

          skip error.message
        end
        begin
          sender.send('hello', 0, '127.0.0.1', port)
          packet = source.next_packet(timeout: 2)
          expect(packet).to be_a(Redhound::Packet)
          expect(packet.caplen).to eq(36)
          expect(packet.original_length).to eq(RUBY_PLATFORM.include?('linux') ? 47 : 37)
          expect(packet.timestamp_ns).to be_within(1_000_000_000).of(Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond))
          expect(source.next_packet(timeout: 0.1)).to be_nil
          expect(source.stats.received).to be >= 1
        ensure
          source.close
        end
      end
    end
  end

  it 'wakes an idle reader when stopped from another thread' do
    source = Redhound::Capture.open(interface: loopback, promiscuous: false, filter: 'udp dst port 9')
    thread = Thread.new { source.next_packet }
    source.stop
    expect(thread.join(0.3)).to eq(thread)
  ensure
    source&.close
    thread&.kill
  end

  %i[socket auto ring].each do |backend|
    it "captures any as Linux SLL2 with a physical interface identity via #{backend}" do
      skip 'Linux-only interface' unless RUBY_PLATFORM.include?('linux')
      with_udp do |sender, port|
        begin
          source = Redhound::Capture.open(interface: 'any', backend:, promiscuous: false, filter: "udp dst port #{port}")
        rescue Redhound::UnsupportedPlatform => error
          raise unless backend == :ring

          skip error.message
        end
        begin
          sender.send('any', 0, '127.0.0.1', port)
          packet = source.next_packet(timeout: 2)
          expect(packet.linktype).to eq(276)
          expect(packet.interface.name).to eq('lo')
          expect(packet.data.bytesize).to eq(51)
          expect(packet.data.unpack1('N', offset: 4)).to eq(packet.interface.index)
        ensure
          source.close
        end
      end
    end
  end

  it 'drops user and group privileges permanently after capture setup' do
    skip 'root is required for privilege dropping' unless Process.uid.zero?
    library = File.expand_path('../../lib', __dir__)
    code = <<~RUBY
      require 'redhound'
      require 'etc'
      account = Etc.getpwnam('nobody')
      source = Redhound::Capture.open(interface: #{loopback.inspect}, promiscuous: false)
      begin
        Redhound::CLI::Privileges.drop('nobody')
        abort 'wrong identity' unless Process.uid == account.uid && Process.gid == account.gid
        begin
          Process::Sys.setuid(0)
          abort 'root can be regained'
        rescue Errno::EPERM
        end
      ensure
        source.close
      end
    RUBY
    _out, err, status = Open3.capture3(RbConfig.ruby, '-I', library, '-e', code)
    expect(status.success?).to be(true), err
  end

  if RUBY_PLATFORM.include?('darwin')
    it 'captures filtered outgoing Ethernet on en0 and preserves it in pcapng' do
      marker = "redhound-ethernet-#{Process.pid}"
      expression = 'udp dst port 54321'
      source = Redhound::Capture.open(interface: 'en0', backend: :bpf, promiscuous: false,
                                     direction: :out, filter: expression)
      UDPSocket.open { |socket| socket.send(marker, 0, '192.0.2.1', 54321) }
      packet = source.next_packet(timeout: 2)
      expect(packet).to be_a(Redhound::Packet)
      expect(packet.linktype).to eq(1)
      expect(packet.direction).to eq(:out)
      expect(packet['udp.dstport']).to eq(54321)
      expect(packet.data).to include(marker)
      io = StringIO.new
      Redhound::Writer.open(io, format: :pcapng, filter: expression) { |writer| writer << packet }
      io.rewind
      Redhound.open(io) do |reader|
        restored = reader.next_packet
        expect(restored.data).to eq(packet.data)
        expect(restored.interface.filter).to eq(expression)
        expect(restored.direction).to eq(:out)
      end
    ensure
      source&.close
    end
  end
end
