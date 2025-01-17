# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L4
    class Base
      class << self
        # @rbs (bytes: Array[Integer]) -> Redhound::L4::Base
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      # @rbs (bytes: Array[Integer]) -> void
      def initialize(bytes:)
        warn 'initialize method must be implemented'
      end

      # @rbs () -> Redhound::L4::Base
      def generate
        warn 'generate method must be implemented'
        self
      end

      # @rbs () -> void
      def dump
        puts self
      end
    end
  end
end
