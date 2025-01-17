# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L3
    class Ipv4 < Base
      class << self
        # @rbs (bytes: Array[Integer]) -> Redhound::L3::Ipv4
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      attr_reader :protocol #: Protocol

      # @rbs (bytes: Array[Integer]) -> void
      def initialize(bytes:)
        raise ArgumentError, "bytes must be #{size} bytes" unless bytes.size >= size

        @bytes = bytes
      end

      # @rbs () -> Redhound::L3::Ipv4
      def generate
        @version = @bytes[0]
        @ihl = @bytes[0]
        @tos = @bytes[1]
        @tot_len = @bytes[2..3]
        @id = @bytes[4..5]
        @frag_off = @bytes[6..7]
        @ttl = @bytes[8]
        @protocol = Protocol.new(protocol: @bytes[9])
        @check = @bytes[10..11]
        @saddr = @bytes[12..15]
        @daddr = @bytes[16..19]
        self
      end

      # @rbs () -> Integer
      def size = 20

      # @rbs () -> String
      def to_s
        " └─ IPv4 Ver: #{version} IHL: #{ihl} TOS: #{@tos} Total Length: #{tot_len} ID: #{id} Offset: #{frag_off} TTL: #{@ttl} Protocol: #{@protocol} Checksum: #{check} Src: #{saddr} Dst: #{daddr}"
      end

      # @rbs () -> bool
      def supported_protocol?
        @protocol.udp? || @protocol.icmp? # steep:ignore
      end

      private

      # @rbs () -> Integer
      def version
        @version & 0xF0
      end

      # @rbs () -> Integer
      def ihl
        @ihl & 0x0F
      end

      # @rbs () -> Integer
      def tot_len
        @tot_len.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> Integer
      def id
        @id.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> Integer
      def frag_off
        @frag_off.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16) & 0x1FFF
      end

      # @rbs () -> Integer
      def check
        @check.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> String
      def saddr
        @saddr.join('.')
      end

      # @rbs () -> String
      def daddr
        @daddr.join('.')
      end
    end
  end
end
