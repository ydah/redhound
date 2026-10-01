# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Util
    # @api private
    module Seq
      MOD = 4_294_967_296
      # @rbs (Integer a, Integer b) -> Integer
      def self.diff(a, b) = (a - b) % MOD
      # @rbs (Integer a, Integer b) -> bool
      def self.lt(a, b) = diff(a, b) >= (MOD >> 1)
      # @rbs (Integer a, Integer b) -> Integer
      def self.signed_diff(a, b)
        delta = diff(a, b)
        delta >= (MOD >> 1) ? delta - MOD : delta
      end
    end
  end
end
