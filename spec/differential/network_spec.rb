# frozen_string_literal: true

require 'json'
require 'open3'
require 'tmpdir'
require_relative '../fixtures/generators/network'

RSpec.describe 'network fields compared with tshark', :differential do
  include NetworkFixtures

  # Raw sequence numbers, option bodies and the 32-bit VXLAN header are API representations;
  # tshark displays relative numbers, complete option TLVs and a 16-bit flag word respectively.
  FIELD_MAP = {
    'tcp.seq' => 'tcp.seq_raw', 'tcp.ack' => 'tcp.ack_raw', 'tcp.flags.ecn' => 'tcp.flags.ece',
    'vlan.priority' => %w[ieee8021ad.priority vlan.priority], 'vlan.dei' => %w[ieee8021ad.dei vlan.dei],
    'vlan.id' => %w[ieee8021ad.id vlan.id], 'vlan.etype' => %w[ieee8021ah.etype vlan.etype],
    'gre.flags' => 'gre.flags_and_version', 'llc.pid' => 'llc.type',
    'ipv6.fragment.offset' => 'ipv6.fraghdr.offset', 'ipv6.fragment.more' => 'ipv6.fraghdr.more',
    'ipv6.fragment.id' => 'ipv6.fraghdr.ident',
    'ipv6.nxt' => %w[ipv6.nxt ipv6.hopopts.nxt ipv6.routing.nxt ipv6.dstopts.nxt ipv6.fraghdr.nxt ah.next_header]
  }.freeze
  INTEGER_FIELDS = %w[
    eth.type vlan.priority vlan.dei vlan.id vlan.etype llc.dsap llc.ssap llc.control llc.pid
    arp.hw.type arp.proto.type arp.hw.size arp.proto.size arp.opcode
    sll.pkttype sll.hatype sll.halen sll.etype sll.ifindex null.family
    ip.version ip.hdr_len ip.len ip.id ip.flags.df ip.flags.mf ip.frag_offset ip.ttl ip.proto ip.checksum
    ipv6.version ipv6.tclass ipv6.flow ipv6.plen ipv6.nxt ipv6.hlim ipv6.fragment.offset ipv6.fragment.more ipv6.fragment.id
    icmp.type icmp.code icmp.checksum icmp.ident icmp.seq icmp.mtu icmpv6.type icmpv6.code icmpv6.checksum
    icmpv6.echo.identifier icmpv6.echo.sequence_number icmpv6.nd.na.flag
    icmpv6.nd.ra.cur_hop_limit icmpv6.nd.ra.flag icmpv6.nd.ra.router_lifetime
    icmpv6.nd.ra.reachable_time icmpv6.nd.ra.retrans_timer icmpv6.opt.type icmpv6.opt.length
    icmpv6.opt.prefix.length icmpv6.opt.prefix.flag icmpv6.opt.prefix.valid_lifetime
    icmpv6.opt.prefix.preferred_lifetime icmpv6.opt.mtu
    igmp.type igmp.version igmp.max_resp igmp.checksum igmp.num_src igmp.num_grp_recs igmp.record_type igmp.qrv igmp.qqic
    udp.srcport udp.dstport udp.length udp.checksum tcp.srcport tcp.dstport tcp.seq tcp.ack tcp.hdr_len tcp.flags
    tcp.window_size_value tcp.checksum tcp.urgent_pointer tcp.options.mss_val tcp.options.wscale.shift
    tcp.options.timestamp.tsval tcp.options.timestamp.tsecr gre.flags gre.proto gre.key vxlan.vni
  ].freeze
  STRING_FIELDS = %w[
    eth.src eth.dst arp.src.hw_mac arp.src.proto_ipv4 arp.dst.hw_mac arp.dst.proto_ipv4 ip.src ip.dst ipv6.src ipv6.dst
    icmpv6.nd.ns.target_address icmpv6.nd.na.target_address icmpv6.nd.rd.target_address
    icmpv6.rd.na.destination_address icmpv6.opt.linkaddr icmpv6.opt.prefix igmp.maddr igmp.saddr
  ].freeze
  BOOLEAN_FIELDS = %w[
    tcp.flags.fin tcp.flags.syn tcp.flags.reset tcp.flags.push tcp.flags.ack tcp.flags.urg tcp.flags.ecn tcp.flags.cwr
    icmpv6.nd.na.flag.r icmpv6.nd.na.flag.s icmpv6.nd.na.flag.o icmpv6.nd.ra.flag.m icmpv6.nd.ra.flag.o
    icmpv6.opt.prefix.flag.l icmpv6.opt.prefix.flag.a igmp.s
  ].freeze

  def collect_fields(node, names)
    case node
    when Hash
      node.flat_map { |key, value| Array(names).include?(key) ? Array(value) : collect_fields(value, names) }
    when Array then node.flat_map { |value| collect_fields(value, names) }
    else []
    end
  end

  def integers(values) = values.map { |value| value.is_a?(Integer) ? value : Integer(value, value.start_with?('0x') ? 16 : 10) }

  def compare_network(packet, reference)
    aggregate_failures("frame #{packet.number}, linktype #{packet.linktype}") do
      INTEGER_FIELDS.each do |name|
        tshark_name = name == 'eth.type' && packet[:eth]&.[](:type).to_i.between?(1, 1500) ? 'eth.len' : FIELD_MAP.fetch(name, name)
        expected = collect_fields(reference, tshark_name)
        # tshark publishes an additional ip.version alias from its IPv6 dissector.
        expected = expected.reject { |value| value == '6' } if name == 'ip.version'
        actual = packet.field_values(name)
        expect(integers(actual)).to eq(integers(expected)), "frame #{packet.number} linktype #{packet.linktype} #{name}: #{actual.inspect} != #{expected.inspect}"
      end
      STRING_FIELDS.each { |name| expect(packet.field_values(name)).to eq(collect_fields(reference, name)), "frame #{packet.number} #{name}: #{packet.field_values(name).inspect} != #{collect_fields(reference, name).inspect}" }
      BOOLEAN_FIELDS.each do |name|
        expected = collect_fields(reference, FIELD_MAP.fetch(name, name)).map { |value| %w[1 True].include?(value) }
        expect(packet.field_values(name)).to eq(expected), name
      end
      expect(packet.field_values('tcp.options.sack_perm')).to eq(collect_fields(reference, 'tcp.options.sack_perm').map { true })
      %w[tcp.options.sack tcp.options.tfo.cookie].each do |name|
        expected = collect_fields(reference, name).map { |value| [value.delete(':')].pack('H*') }
        expected.map! { |value| value.byteslice(2..) } if name == 'tcp.options.sack'
        expect(packet.field_values(name)).to eq(expected), name
      end
      expected_flags = integers(collect_fields(reference, 'vxlan.flags')).map { |value| value << 16 }
      expect(packet.field_values('vxlan.flags')).to eq(expected_flags), 'vxlan.flags'
    end
  end

  before do
    skip 'tshark is not installed' unless system('tshark', '--version', out: File::NULL, err: File::NULL)
  end

  it 'matches every network family, options, embedded packets and tunnels in the committed corpus' do
    path = File.expand_path('../fixtures/pcap/network.pcap', __dir__)
    packets = Redhound.open(path).to_a
    json, error, status = Open3.capture3('tshark', '-n', '-r', path, '-T', 'json', '--no-duplicate-keys')
    expect(status.success?).to be(true), error
    reference = JSON.parse(json)
    expect(reference.length).to eq(packets.length)
    aggregate_failures do
      packets.zip(reference).each { |packet, node| compare_network(packet, node.dig('_source', 'layers')) }
    end
  end

  it 'matches SLL, SLL2, BSD Null, Loop and raw IPv4/IPv6 capture link types' do
    Dir.mktmpdir('redhound-network') do |dir|
      aggregate_failures do
        linktype_frames.each_with_index do |(name, (linktype, bytes)), index|
          packet = Redhound::Packet.new(bytes, linktype: linktype, timestamp_ns: 1_700_000_000_000_000_000, number: index + 1)
          path = File.join(dir, "#{name}.pcap")
          writer = Redhound::File::PcapWriter.new(path, linktype: linktype)
          writer.write(packet)
          writer.close
          json, error, status = Open3.capture3('tshark', '-n', '-r', path, '-T', 'json', '--no-duplicate-keys')
          expect(status.success?).to be(true), error
          compare_network(packet, JSON.parse(json).first.dig('_source', 'layers'))
        end
      end
    end
  end
end
