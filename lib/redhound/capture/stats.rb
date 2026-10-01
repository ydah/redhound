# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    class Stats
      attr_accessor :received, :dropped, :if_dropped, :freeze_count, :captured

      # @rbs (?received: Integer, ?dropped: Integer, ?if_dropped: Integer, ?freeze_count: Integer, ?captured: Integer) -> void
      def initialize(received: 0, dropped: 0, if_dropped: 0, freeze_count: 0, captured: 0)
        @received, @dropped, @if_dropped, @freeze_count, @captured = received, dropped, if_dropped, freeze_count, captured
      end

      # @rbs () -> Hash[Symbol, Integer]
      def to_h
        { received: @received, dropped: @dropped, if_dropped: @if_dropped, freeze_count: @freeze_count, captured: @captured }
      end
    end
  end
end
