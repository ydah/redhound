# rbs_inline: enabled
# frozen_string_literal: true

require_relative 'redhound/version'

require_relative 'redhound/errors'
require_relative 'redhound/cursor'
require_relative 'redhound/diagnostic'
require_relative 'redhound/field'
require_relative 'redhound/layer'
require_relative 'redhound/registry'
require_relative 'redhound/dissector'
require_relative 'redhound/stream_dissector'
require_relative 'redhound/context'
require_relative 'redhound/engine'
require_relative 'redhound/capture/linktype'
require_relative 'redhound/packet'
require_relative 'redhound/protocols/checksum'
require_relative 'redhound/protocols/data'
require_relative 'redhound/protocols/ethernet'
require_relative 'redhound/protocols/vlan'
require_relative 'redhound/protocols/llc'
require_relative 'redhound/protocols/link'
require_relative 'redhound/protocols/arp'
require_relative 'redhound/protocols/ipv4'
require_relative 'redhound/protocols/ipv6'
require_relative 'redhound/protocols/udp'
require_relative 'redhound/protocols/tcp'
require_relative 'redhound/protocols/icmp'
require_relative 'redhound/protocols/tunnel'
require_relative 'redhound/protocols/dns'
require_relative 'redhound/protocols/dhcp'
require_relative 'redhound/protocols/ntp'
require_relative 'redhound/protocols/http'
require_relative 'redhound/protocols/tls'
require_relative 'redhound/output/timestamp'
require_relative 'redhound/output/summary'
require_relative 'redhound/output/tree'
require_relative 'redhound/output/hexdump'
require_relative 'redhound/output/json'
require_relative 'redhound/output/fields'
require_relative 'redhound/filter'
require_relative 'redhound/capture'
require_relative 'redhound/writer'
require_relative 'redhound/analysis'
require_relative 'redhound/cli/options'
require_relative 'redhound/cli/privileges'
require_relative 'redhound/cli/runner'
require_relative 'redhound/cli/command'

# Capture, inspect and save network packets using Ruby standard libraries.
module Redhound
  # @rbs (String bytes, ?linktype: (Integer | Symbol), **untyped metadata) -> Packet
  # Create a packet with lazy, bounded protocol dissection. See docs/API.md.
  def self.dissect(bytes, linktype: :ethernet, **metadata)
    Packet.new(bytes, linktype: linktype, **metadata)
  end

  # @rbs (untyped input, ?filter: String?) -> Reader
  # @rbs [T] (untyped input, ?filter: String?) { (Reader) -> T } -> T
  # Read a pcap/pcapng path or binary IO; a block closes the reader automatically.
  def self.open(input, filter: nil)
    reader = Reader.new(input, filter: filter)
    return reader unless block_given?
    begin
      yield reader
    ensure
      reader.close
    end
  end

  # @rbs (interface: String | Integer, ?count: Integer?, **untyped options) { (Packet) -> void } -> void
  # Yield live packets until count is reached or capture stops; always close the source.
  def self.capture(interface:, count: nil, **options)
    raise ConfigurationError, 'count must be positive' if count && count <= 0
    Capture.open(interface: interface, **options) do |source|
      captured = 0
      source.each_packet do |packet|
        yield packet
        captured += 1
        break if count && captured >= count
      end
    end
  end
end
