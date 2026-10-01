# frozen_string_literal: true
require 'spec_helper'
require 'redhound/filter'

RSpec.describe Redhound::Filter do
  def filter_packet(data, linktype: 1, length: data.bytesize, meta: {})
    Struct.new(:data, :linktype, :original_length, :meta).new(data, linktype, length, meta)
  end

  let(:dns) { filter_packet(ether(ipv4(udp('x'.b)))) }
  let(:web) { filter_packet(ether(ipv4(tcp(dport: 443), proto: 6))) }

  it 'compiles qualified primitives and inherited qualifiers to cBPF' do
    expect(described_class.compile('ip and udp dst port 53').match?(dns)).to be true
    expect(described_class.compile('tcp dst port (80 or 443)').match?(web)).to be true
    expect(described_class.compile('tcp dst port 80 or 443').match?(dns)).to be false
    expect(described_class.compile('src host 192.0.2.1 and net 192.0.2.0/24').match?(web)).to be true
    expect(described_class.compile('ether src host 02:00:00:00:00:01').match?(web)).to be true
  end

  it 'uses tcpdump equal precedence for and/or and higher precedence for negation' do
    expect(described_class.compile('udp or tcp and dst port 443').match?(dns)).to be false
    expect(described_class.compile('udp or (tcp and dst port 443)').match?(dns)).to be true
    expect(described_class.compile('not tcp and udp').match?(dns)).to be true
  end

  it 'rejects noninitial IPv4 fragments for transport offsets' do
    fragment = ether(ipv4(udp('x'.b)))
    fragment[20, 2] = [1].pack('n')
    packet = filter_packet(fragment)
    expect(described_class.compile('udp').match?(packet)).to be true
    expect(described_class.compile('udp port 53').match?(packet)).to be false
    expect(described_class.compile('udp[2:2] = 53').match?(packet)).to be false
  end

  it 'compiles arithmetic with unsigned 32-bit semantics and protocol guards' do
    expect(described_class.compile('tcp[tcpflags] & (tcp-syn|tcp-fin) != 0').match?(web)).to be true
    expect(described_class.compile('(ip[0] & 15) * 4 = 20').match?(dns)).to be true
    expect(described_class.compile('udp[2:2] = 53 and ip[2:2] < len').match?(dns)).to be true
    expect(described_class.compile('len / 2 >= 30 and len - 60 = 0').match?(dns)).to be true
    expect(described_class.compile('tcp[13] = 2').match?(dns)).to be false
    expect(described_class.compile('1 + 1 = 2').match?(dns)).to be true
    expect(described_class.compile('-1 = 0xffffffff').match?(dns)).to be true
    icmpv6 = filter_packet(ether(ipv6("\x80".b * 8, next_header: 58), type: 0x86dd))
    expect(described_class.compile('icmp6[0] = 128').match?(icmpv6)).to be true
  end

  it 'supports inline VLAN offsets, nested VLANs, and stripped VLAN metadata' do
    frame = ether([100, 0x0800].pack('nn') + ipv4(udp('x'.b)), type: 0x8100)
    expect(described_class.compile('vlan 100 and udp port 53').match?(filter_packet(frame))).to be true
    expect(described_class.compile('vlan 101 and udp port 53').match?(filter_packet(frame))).to be false
    expect(described_class.compile('vlan 100 and udp port 53', live: true).match?(filter_packet(frame))).to be true
    stripped = filter_packet(dns.data, meta: { vlan_tci: 100 })
    expect(described_class.compile('vlan 100 and udp port 53', live: true).match?(stripped)).to be true
    expect(described_class.compile('vlan 101 and udp port 53', live: true).match?(stripped)).to be false
  end

  it 'resolves host and service names at compile time' do
    expect(described_class.compile('udp port domain').match?(dns)).to be true
    loopback = filter_packet(ether(ipv4(udp('x'.b), src: '127.0.0.1')))
    expect(described_class.compile('host localhost').match?(loopback)).to be true
  end

  it 'compiles Linux any filters for kernel network bytes and evaluates cooked packets' do
    header = [0x0800, 0, 1, 1, 0, 6].pack('nnNnCC') + mac('02:00:00:00:00:01').ljust(8, "\0")
    packet = filter_packet(header + ipv4(udp('x'.b)), linktype: 276)
    program = described_class.compile('ip and udp dst port 53 and len > 40', linktype: 276, live: true)
    expect(program.match?(packet)).to be true
    expect(program.instructions).to include([0x20, 0, 0, 0xfffff000])
    expect(described_class.compile('', snaplen: 1 << 24).evaluate(dns)).to eq(1 << 24)
  end

  it 'reports source positions and rejects unsupported or mistyped qualifiers' do
    ['tcp prot 80', 'port 192.0.2.1', 'port 65536', 'ip6 host 192.0.2.1', 'ether port 80',
     'tcp net 192.0.2.0/24', 'ip proto 256', 'vlan 4096', 'ip[0:3] = 0', 'ip[0] / 0 = 1',
     'ip protochain tcp', 'gateway localhost', 'udp and'].each do |expression|
      expect { described_class.compile(expression) }.to raise_error(Redhound::FilterSyntaxError) do |error|
        expect(error.expression).to eq(expression)
        expect(error.position).to be_a(Integer)
      end
    end
  end

  it 'allows forward jumps beyond conditional byte ranges and bounds program size' do
    expression = (1..120).map { |port| "udp dst port #{port}" }.join(' or ')
    expect(described_class.compile(expression).match?(dns)).to be true
    expect(described_class.compile('', snaplen: 99).evaluate(dns)).to eq(99)
    expect { described_class.compile(Array.new(500, 'tcp port 443').join(' or ')) }.to raise_error(Redhound::FilterTooLarge)
  end
end
