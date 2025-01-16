# frozen_string_literal: true

module Redhound
  class Header
    class Icmp
      class << self
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      def initialize(bytes:)
        raise ArgumentError, "bytes must be bigger than #{size} bytes" unless bytes.size >= size

        @bytes = bytes
      end

      def generate
        @type = @bytes[0]
        @code = @bytes[1]
        @check = @bytes[2..3]
        # refs: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
        if @type.zero? || @type == 8
          @id = @bytes[4..5]
          @seq = @bytes[6..7]
          @data = @bytes[8..]
        else
          @data = @bytes[4..]
        end
        self
      end

      def size = 8

      def dump
        puts self
      end

      def to_s
        if @type.zero? || @type == 8
          <<-ICMP.chomp
    └─ ICMP Type: #{@type} Code: #{@code} Checksum: #{check} ID: #{id} Sequence: #{seq}
        └─ Payload: #{data}
          ICMP
        else
          <<-ICMP.chomp
    └─ ICMP Type: #{@type} Code: #{@code} Checksum: #{check}
        └─ Payload: #{data}
          ICMP
        end
      end

      private

      def check
        @check.map { |b| b.to_s(16).rjust(2, '0') }.join
      end

      def id
        @id.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      def seq
        @seq.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
      end

      def data
        @data.map(&:chr).join.force_encoding("UTF-8")
      end
    end
  end
end
