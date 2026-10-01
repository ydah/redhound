# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    class Source
      include Enumerable #[Packet]

      # @rbs () -> void
      def initialize
        @stopped = false
        @closed = false
        @number = 0
        @capture_stats = Stats.new
      end

      # @rbs () { (Packet) -> void } -> self
      # @rbs () -> Enumerator[Packet, self]
      def each_packet
        return enum_for(:each_packet) unless block_given?

        until @stopped || @closed
          packet = next_packet(timeout: 0.1)
          yield packet if packet
        end
        self
      end

      alias each each_packet

      # @rbs (?timeout: Numeric?) -> Packet?
      def next_packet(timeout: nil)
        raise NotImplementedError
      end

      # @rbs () -> Stats
      def stats = @capture_stats

      # @rbs () -> bool
      def stopped? = @stopped

      # @rbs () -> void
      def stop
        @stopped = true
      end

      # @rbs () -> void
      def close
        stop
        @closed = true
      end

      private

      # @rbs (IO io, Numeric? deadline) -> bool
      def wait_readable(io, deadline)
        until @stopped || @closed
          remaining = deadline && deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          return !!IO.select([io], nil, nil, 0) if remaining && remaining <= 0
          return true if IO.select([io], nil, nil, remaining ? [remaining, 0.1].min : 0.1)
        end
        false
      rescue IOError, Errno::EBADF
        return false if @closed || @stopped

        raise
      end

      # @rbs (Numeric? timeout) -> Numeric?
      def deadline_for(timeout)
        raise ArgumentError, 'timeout must be nonnegative' if timeout && timeout.negative?

        timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      end
    end
  end
end
