# frozen_string_literal: true

require 'spec_helper'

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

  it 'captures filtered UDP with kernel time, original length and bounded snaplen' do
    backends = RUBY_PLATFORM.include?('linux') ? %i[socket ring] : [:bpf]
    with_udp do |sender, port|
      backends.each do |backend|
        source = Redhound::Capture.open(interface: loopback, backend:, snaplen: 36, promiscuous: false,
                                        filter: "udp dst port #{port}")
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

  it 'captures any as Linux SLL2 with a physical interface identity' do
    skip 'Linux-only interface' unless RUBY_PLATFORM.include?('linux')
    with_udp do |sender, port|
      source = Redhound::Capture.open(interface: 'any', backend: :ring, promiscuous: false, filter: "udp dst port #{port}")
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
