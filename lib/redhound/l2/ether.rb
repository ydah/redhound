# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L2
    class Ether
      attr_reader :type #: Protocol

      class << self
        # @rbs (bytes: Array[Integer], count: Integer) -> Redhound::L2::Ether
        def generate(bytes:, count:)
          new(bytes:, count:).generate
        end
      end

      # @rbs (bytes: Array[Integer], count: Integer) -> void
      def initialize(bytes:, count:)
        raise ArgumentError, "bytes must be #{size} bytes" unless bytes.size >= size

        @bytes = bytes
        @count = count
      end

      # @rbs () -> Integer
      def size = 14

      # @rbs () -> Redhound::L2::Ether
      def generate
        @dhost = @bytes[0..5]
        @shost = @bytes[6..11]
        @type = Protocol.new(protocol: hex_type(@bytes[12..13]))
        self
      end

      # @rbs () -> void
      def dump
        puts self
      end

      # @rbs () -> String
      def to_s
        "[#{@count}] Ethernet Dst: #{dhost} Src: #{shost} Type: #{@type}"
      end

      # @rbs () -> bool
      def supported_type?
        @type.ipv4? || @type.ipv6? || @type.arp? # steep:ignore
      end

      private

      # @rbs () -> String
      def dhost
        @dhost.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      # @rbs () -> String
      def shost
        @shost.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      # @rbs (Array[Integer] type) -> Integer
      def hex_type(type)
        type.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end
    end
  end
end
