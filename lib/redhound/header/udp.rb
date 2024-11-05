module Redhound
  class Header
    class Udp
      class << self
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      def initialize(bytes:)
        raise ArgumentError, 'bytes must be bigger than 8 bytes' unless bytes.size >= 8
        @bytes = bytes
      end

      def generate
        @sport = @bytes[0..1]
        @dport = @bytes[2..3]
        @len = @bytes[4..5]
        @check = @bytes[6..7]
        @data = @bytes[8..-1]
        self
      end

      def dump
        puts "UDP HEADER----------------"
        puts self
      end

      def to_s
        <<~UDP
          Source Port: #{sport}
          Destination Port: #{dport}
          Length: #{len}
          Checksum: #{check}
          Data: #{data}
        UDP
      end

      def sport
        @sport.map { |b| b.to_s(16).rjust(2, "0") }.join.to_i(16)
      end

      def dport
        @dport.map { |b| b.to_s(16).rjust(2, "0") }.join.to_i(16)
      end

      def len
        @len.map { |b| b.to_s(16).rjust(2, "0") }.join.to_i(16)
      end

      def check
        @check.map { |b| b.to_s(16).rjust(2, "0") }.join.to_i(16)
      end

      def data
        @data.map { |b| b.chr }.join
      end
    end
  end
end
