# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L3
    class Resolver
      # @rbs (bytes: Array[Integer], l2: Redhound::L2::Ether) -> Redhound::L3::Base?
      def self.resolve(bytes:, l2:)
        new(bytes:, l2:).resolve
      end

      # @rbs (bytes: Array[Integer], l2: Redhound::L2::Ether) -> void
      def initialize(bytes:, l2:)
        @bytes = bytes
        @l2 = l2
      end

      # @rbs () -> Redhound::L3::Base?
      def resolve
        if @l2.type.ipv4?
          Ipv4.generate(bytes: @bytes)
        elsif @l2.type.ipv6?
          Ipv6.generate(bytes: @bytes)
        elsif @l2.type.arp?
          Arp.generate(bytes: @bytes)
        end
      end
    end
  end
end
