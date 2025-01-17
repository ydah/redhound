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
        @type = Redhound::L2::Protocol.new(protocol: ptype)
        @l3 = generate_l3
        self
      end

      # @rbs () -> Integer
      def arp_size = 28

      # @rbs () -> Integer
      def size
        if @l3.nil?
          arp_size
        else
          arp_size + @l3.size
        end
      end

      # @rbs () -> String
      def to_s
        "    └─ ARP HType: #{htype} PType: #{ptype} HLen: #{@hlen} PLen: #{@plen} Oper: #{oper} SHA: #{sha} SPA: #{spa} THA: #{tha} TPA: #{tpa}"
      end

      # @rbs () -> bool
      def supported_protocol?
        return false if @l3.nil?
        @l3.supported_protocol?
      end

      # @rbs () -> String?
      def protocol
        @l3.protocol if @l3
      end

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
        @spa.map { |b| b.to_s(16).rjust(2, '0') }.join('.')
      end

      # @rbs () -> String
      def tha
        @tha.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      # @rbs () -> String
      def tpa
        @tpa.map { |b| b.to_s(16).rjust(2, '0') }.join('.')
      end

      # @rbs () -> Redhound::L3::Base?
      def generate_l3
        return if @bytes.size == arp_size

        if @type.ipv4?
          Ipv4.generate(bytes: @bytes[arp_size..])
        elsif @type.ipv6?
          Ipv6.generate(bytes: @bytes[arp_size..])
        end
      end
    end
  end
end
