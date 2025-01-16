# frozen_string_literal: true

module Redhound
  class Header
    class Ipv4
      class << self
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      attr_reader :protocol

      def initialize(bytes:)
        raise ArgumentError, "bytes must be #{size} bytes" unless bytes.size >= size

        @bytes = bytes
      end

      def generate
        @version = @bytes[0]
        @ihl = @bytes[0]
        @tos = @bytes[1]
        @tot_len = @bytes[2..3]
        @id = @bytes[4..5]
        @frag_off = @bytes[6..7]
        @ttl = @bytes[8]
        @protocol = InternetProtocol.new(protocol: @bytes[9])
        @check = @bytes[10..11]
        @saddr = @bytes[12..15]
        @daddr = @bytes[16..19]
        self
      end

      def size = 20

      def dump
        puts self
      end

      def to_s
        " └─ IPv4 Ver: #{version} IHL: #{ihl} TOS: #{@tos} Total Length: #{tot_len} ID: #{id} Offset: #{frag_off} TTL: #{@ttl} Protocol: #{@protocol} Checksum: #{check} Src: #{saddr} Dst: #{daddr}"
      end

      def supported_protocol?
        @protocol.udp? || @protocol.icmp?
      end

      private

      def version
        @version & 0xF0
      end

      def ihl
        @ihl & 0x0F
      end

      def tot_len
        @tot_len.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      def id
        @id.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      def frag_off
        @frag_off.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16) & 0x1FFF
      end

      def check
        @check.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      def saddr
        @saddr.join('.')
      end

      def daddr
        @daddr.join('.')
      end
    end
  end
end
