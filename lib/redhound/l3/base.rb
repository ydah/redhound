# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L3
    class Base
      class << self
        # @rbs (bytes: Array[Integer]) -> Redhound::L3::Base
        def generate(bytes:)
          new(bytes:).generate
        end
      end

      # @rbs (bytes: Array[Integer]) -> void
      def initialize(bytes:)
        warn 'initialize method must be implemented'
      end

      # @rbs () -> Redhound::L3::Base
      def generate
        warn 'generate method must be implemented'
        self
      end

      # @rbs () -> void
      def dump
        puts self
      end

      # @rbs () -> Integer
      def size
        warn 'size method must be implemented'
        0
      end

      # @rbs () -> bool
      def supported_protocol?
        warn 'supported_protocol? method must be implemented'
        false
      end

      # @rbs () -> Protocol
      def protocol
        warn 'protocol method must be implemented'
        Protocol.new(protocol: 0)
      end
    end
  end
end
