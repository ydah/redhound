# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L3
    class Arp < Base
      class << self
        # @rbs (bytes: Array[Integer]) -> Redhound::L3::Arp
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      # @rbs (bytes: Array[Integer]) -> void
      def initialize(bytes:)
        raise ArgumentError, "bytes must be bigger than #{arp_size} bytes" unless bytes.size >= arp_size

        @bytes = bytes
      end

      # @rbs () -> Redhound::L3::Arp
      def generate
        @htype = @bytes[0..1]
        @ptype = @bytes[2..3]
        @hlen = @bytes[4]
        @plen = @bytes[5]
        @oper = @bytes[6..7]
        @sha = @bytes[8..13]
        @spa = @bytes[14..17]
        @tha = @bytes[18..23]
        @tpa = @bytes[24..27]
        self
      end

      # @rbs () -> Integer
      def arp_size = 28

      # @rbs () -> Integer
      def size = arp_size

      # @rbs () -> String
      def to_s
        "    └─ ARP HType: #{htype} PType: #{ptype} HLen: #{@hlen} PLen: #{@plen} Oper: #{oper} SHA: #{sha} SPA: #{spa} THA: #{tha} TPA: #{tpa}"
      end

      # ARP は上位プロトコルを運ばない
      # @rbs () -> bool
      def supported_protocol? = false

      # @rbs () -> nil
      def protocol = nil

      private

      # @rbs () -> Integer
      def htype
        @htype.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> Integer
      def ptype
        @ptype.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> Integer
      def oper
        @oper.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      # @rbs () -> String
      def sha
        @sha.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      # @rbs () -> String
      def spa
        @spa.join('.')
      end

      # @rbs () -> String
      def tha
        @tha.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      # @rbs () -> String
      def tpa
        @tpa.join('.')
      end

    end
  end
end
