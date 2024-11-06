# frozen_string_literal: true

module Redhound
  class Header
    class Ether
      ETH_P_IP = 0x0800

      class << self
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      def initialize(bytes:)
        raise ArgumentError, 'bytes must be 14 bytes' unless bytes.size == 14

        @bytes = bytes
      end

      def generate
        @dhost = @bytes[0..5]
        @shost = @bytes[6..11]
        @type = @bytes[12..13]
        self
      end

      def ipv4?
        hex_type == ETH_P_IP
      end

      def dump
        puts 'ETHERNET HEADER----------------'
        puts self
      end

      def to_s
        <<~ETHER
          Destination MAC: #{dhost}
          Source MAC: #{shost}
          Type: #{type}
        ETHER
      end

      def dhost
        @dhost.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      def shost
        @shost.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
      end

      def type
        if ipv4?
          'IPv4'
        else
          'Unknown'
        end
      end

      private

      def hex_type
        @hex_type ||= @type.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end
    end
  end
end
