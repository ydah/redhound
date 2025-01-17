# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L4
    class Udp < Base
      # @rbs (bytes: Array[Integer]) -> void
      def initialize(bytes:)
        raise ArgumentError, "bytes must be bigger than #{size} bytes" unless bytes.size >= size

        @bytes = bytes
      end

      # @rbs () -> Redhound::L4::Udp
      def generate
        @sport = @bytes[0..1]
        @dport = @bytes[2..3]
        @len = @bytes[4..5]
        @check = @bytes[6..7]
        @data = @bytes[8..]
        self
      end

      # @rbs () -> Integer
      def size = 8

      # @rbs () -> String
      def to_s
        <<-UDP
    └─ UDP Src: #{sport} Dst: #{dport} Len: #{len} Checksum: #{check}
        └─ Payload: #{data}
        UDP
      end

      private

      # @rbs () -> Integer
      def sport
        @sport.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> Integer
      def dport
        @dport.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> Integer
      def len
        @len.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> Integer
      def check
        @check.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> String
      def data
        @data.map(&:chr).join
      end
    end
  end
end
