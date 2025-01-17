# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L4
    class Resolver
      # @rbs (bytes: Array[Integer], l3: Redhound::L3::Base) -> Redhound::L4::Base?
      def self.resolve(bytes:, l3:)
        new(bytes:, l3:).resolve
      end

      # @rbs (bytes: Array[Integer], l3: Redhound::L3::Base) -> void
      def initialize(bytes:, l3:)
        @bytes = bytes
        @l3 = l3
      end

      # @rbs () -> Redhound::L4::Base?
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
