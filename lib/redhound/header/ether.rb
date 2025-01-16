# frozen_string_literal: true

module Redhound
  class Header
    class Ether
      attr_reader :type

      class << self
        def generate(bytes:, count:)
          new(bytes:, count:).generate
        end
      end

      def initialize(bytes:, count:)
        raise ArgumentError, "bytes must be #{size} bytes" unless bytes.size >= size

        @bytes = bytes
        @count = count
      end

      def size = 14

      def generate
        @dhost = @bytes[0..5]
        @shost = @bytes[6..11]
        @type = EthernetProtocol.new(protocol: hex_type(@bytes[12..13]))
        self
      end

      def dump
        puts self
      end

      def to_s
        "[#{@count}] Ethernet Dst: #{dhost} Src: #{shost} Type: #{@type}"
      end

      def dhost
        @dhost.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      def shost
        @shost.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      def supported_type?
        @type.ipv4? || @type.ipv6? || @type.arp?
      end

      private

      def hex_type(type)
        type.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end
    end
  end
end
