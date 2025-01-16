# frozen_string_literal: true

module Redhound
  class L4
    class Resolver
      def self.resolve(bytes:, l3:)
        new(bytes:, l3:).resolve
      end

      def initialize(bytes:, l3:)
        @bytes = bytes
        @l3 = l3
      end

      def resolve
        if @l3.protocol.udp?
          Udp.generate(bytes: @bytes)
        elsif @l3.protocol.icmp?
          Icmp.generate(bytes: @bytes)
        end
      end
    end
  end
end
