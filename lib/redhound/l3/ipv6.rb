# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L3
    class Ipv6 < Base
      class << self
        # @rbs (bytes: Array[Integer]) -> Redhound::L3::Ipv6
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      attr_reader :protocol #: Protocol

      # @rbs (bytes: Array[Integer]) -> void
      def initialize(bytes:)
        raise ArgumentError, "bytes must be bigger than #{size} bytes" unless bytes.size >= size

        @bytes = bytes
      end

      # @rbs () -> Integer
      def size = 40

      # @rbs () -> Redhound::L3::Ipv6
      def generate
        version_traffic_flow = @bytes[0..3].join.to_i(16)
        @version = (version_traffic_flow >> 28) & 0xF
        @traffic_class = (version_traffic_flow >> 20) & 0xFF
        @flow_label = version_traffic_flow & 0xFFFFF
        @payload_length = @bytes[4..5]
        @next_header = @bytes[6]
        @hop_limit = @bytes[7]
        @saddr = @bytes[8..23]
        @daddr = @bytes[24..39]
        @protocol = Protocol.new(protocol: @next_header)
        self
      end

      # @rbs () -> String
      def to_s
        " └─ IPv6 Ver: #{@version} Traffic Class: #{@traffic_class} Flow Label: #{@flow_label} Payload Length: #{payload_length} Next Header: #{@protocol} Hop Limit: #{@hop_limit} Src: #{saddr} Dst: #{daddr}"
      end

      # @rbs () -> bool
      def supported_protocol?
        @protocol.udp? # steep:ignore
      end

      private

      # @rbs () -> Integer
      def payload_length
        @payload_length.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> Integer
      def saddr
        @saddr.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      # @rbs () -> Integer
      def daddr
        @daddr.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end
    end
  end
end
