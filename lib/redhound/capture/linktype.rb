# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Linktype
      VALUES = { null: 0, ethernet: 1, ether: 1, raw: 101, loop: 108, sll: 113,
                 linux_sll: 113, radiotap: 127, ipv4: 228, ipv6: 229, sll2: 276, linux_sll2: 276 }.freeze

      # @rbs (Integer | Symbol | String value) -> Integer
      def self.resolve(value)
        return value if value.is_a?(Integer) && value.between?(0, 65_535)

        VALUES.fetch(value.to_s.downcase.to_sym) { raise ArgumentError, "unknown link type: #{value}" }
      end

      # @rbs (Integer value) -> String
      def self.name(value)
        VALUES.key(value)&.to_s || "LINKTYPE_#{value}"
      end

      # @rbs (Integer hardware_type) -> Integer
      def self.for_hardware(hardware_type)
        { 1 => 1, 772 => 1, 65_534 => 101, 803 => 127 }.fetch(hardware_type, 276)
      end
    end
  end
end
