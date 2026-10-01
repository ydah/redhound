# frozen_string_literal: true

require 'spec_helper'
require 'open3'

RSpec.describe 'Linux veth and VLAN capture', :live do
  def send_udp(address, port, payload)
    code = 'UDPSocket.open { |socket| socket.send(ARGV[2], 0, ARGV[0], Integer(ARGV[1])) }'
    _output, error, status = Open3.capture3('ip', 'netns', 'exec', 'rh-peer', RbConfig.ruby,
                                           '-rsocket', '-e', code, address, port.to_s, payload)
    expect(status.success?).to be(true), error
  end

  it 'matches socket and ring packets and restores offloaded VLAN tags with kernel filtering' do
    skip 'requires Linux and REDHOUND_NETNS=1' unless RUBY_PLATFORM.include?('linux') && ENV['REDHOUND_NETNS'] == '1'
    sources = []
    script_dir = File.expand_path('../../script', __dir__)
    setup_attempted = true
    output, error, status = Open3.capture3('bash', File.join(script_dir, 'netns-setup.sh'))
    expect(status.success?).to be(true), output + error
    skip 'kernel does not support VLAN interfaces' if output.include?('skip VLAN')

    receiver = UDPSocket.new
    receiver.bind('0.0.0.0', 0)
    port = receiver.addr[1]
    marker = "redhound-netns-#{Process.pid}"
    %i[socket ring].each do |backend|
      sources << Redhound::Capture.open(interface: 'rh0', backend:, direction: :in, snaplen: 40,
                                        promiscuous: false, filter: "udp dst port #{port}")
    end
    send_udp('10.99.0.1', port, marker)
    socket_packet, ring_packet = sources.map { |source| source.next_packet(timeout: 2) }
    expect(socket_packet).to be_a(Redhound::Packet)
    expect(ring_packet).to be_a(Redhound::Packet)
    expect(socket_packet.caplen).to eq(40)
    expect(ring_packet.data).to eq(socket_packet.data)
    expect(ring_packet.original_length).to eq(socket_packet.original_length)
    expect((ring_packet.timestamp_ns - socket_packet.timestamp_ns).abs).to be <= 1_000_000
    sources.each(&:close)
    sources.clear

    %i[socket ring].each do |backend|
      sources << Redhound::Capture.open(interface: 'rh0', backend:, direction: :in, promiscuous: false,
                                        filter: "vlan 100 and udp dst port #{port}")
    end
    send_udp('10.99.0.1', port, 'plain traffic must be rejected')
    send_udp('10.99.100.1', port == 65_535 ? port - 1 : port + 1, 'wrong port must be rejected')
    send_udp('10.99.100.1', port, marker)
    socket_packet, ring_packet = sources.map { |source| source.next_packet(timeout: 2) }
    expect(socket_packet).to be_a(Redhound::Packet)
    expect(ring_packet).to be_a(Redhound::Packet)
    expect(ring_packet.meta[:vlan_tci] & 0x0fff).to eq(100)
    expect(ring_packet.data.unpack('n2', offset: 12)).to eq([0x8100, 100])
    expect(ring_packet.data).to include(marker)
    if socket_packet.data.unpack1('n', offset: 12) == 0x8100
      expect(ring_packet.data).to eq(socket_packet.data)
      expect(ring_packet.original_length).to eq(socket_packet.original_length)
    else
      # recvfrom cannot expose VLAN auxiliary data; normalize the ring's restored tag.
      normalized = ring_packet.data.byteslice(0, 12) + ring_packet.data.byteslice(16..)
      expect(normalized).to eq(socket_packet.data)
      expect(ring_packet.original_length).to eq(socket_packet.original_length + 4)
    end
    expect((ring_packet.timestamp_ns - socket_packet.timestamp_ns).abs).to be <= 1_000_000
    sources.each { |source| expect(source.next_packet(timeout: 0.1)).to be_nil }
  ensure
    begin
      sources&.each(&:close)
    ensure
      begin
        receiver&.close
      ensure
        Open3.capture3('bash', File.join(script_dir, 'netns-teardown.sh')) if setup_attempted
      end
    end
  end
end
