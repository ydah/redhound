# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Analysis
    # @api private
    class Flow
      BASE_BYTES = 4096
      attr_reader :key, :id, :first_ns, :packets, :bytes, :streams, :applications, :acks, :keep_alives, :http_methods
      attr_accessor :last_ns, :closed_ns, :syn_ns, :syn_direction, :synack_ns, :synack_seq, :initial_rtt, :accounted_bytes
      # @rbs (untyped key, Integer id, Integer timestamp_ns) -> void
      def initialize(key, id, timestamp_ns)
        @key, @id, @first_ns, @last_ns = key, id, timestamp_ns, timestamp_ns
        @packets, @bytes, @streams, @applications, @acks = [0, 0], [0, 0], [nil, nil], [nil, nil], [nil, nil]
        @keep_alives = [false, false]
        @http_methods = [Array.new, Array.new] #: Array[untyped]
        @closed_ns = @syn_ns = @syn_direction = @synack_ns = @synack_seq = @initial_rtt = nil # @rbs untyped
        @accounted_bytes = BASE_BYTES
      end
      # @rbs () -> bool
      def closed? = !@closed_ns.nil?
      # @rbs () -> Integer
      def bytesize = BASE_BYTES + @streams.compact.sum(&:bytesize) + @applications.compact.sum(&:bytesize) + @http_methods.sum { |methods| methods.size * 16 }
    end

    # @api private
    class FlowTable
      attr_reader :evicted, :expired
      attr_accessor :on_remove
      # @rbs (?max_flows: Integer) -> void
      def initialize(max_flows: 100_000)
        raise ArgumentError, 'max_flows must be positive' unless max_flows.positive?
        @max_flows, @next_id, @evicted, @expired, @clock = max_flows, 0, 0, 0, 0
        @next_sweep, @bytes, @tcp_bytes = 0, 0, 0
        @on_remove = nil # @rbs untyped
        @entries = {} #: Hash[untyped, Flow]
      end
      # @rbs (Packet packet) -> untyped
      def update(packet)
        advance(packet.timestamp_ns)
        result = FlowKey.from(packet)
        return nil unless result
        key, direction = result
        flow = @entries.delete(key)
        transport = packet.layers.reverse.find { |layer| layer.protocol == :tcp && !layer.embedded }
        if flow && transport && transport[:flags] && transport[:flags] & 0x12 == 2
          previous = flow.streams[direction]
          if flow.closed? || (previous && previous.base_seq && previous.base_seq != transport[:seq])
            discard(flow)
            flow = nil
          end
        end
        unless flow
          evict if @entries.size >= @max_flows
          flow = Flow.new(key, key[0] == :tcp ? @next_id : -1, @clock)
          @next_id += 1 if key[0] == :tcp
          @bytes += flow.accounted_bytes
        end
        flow.last_ns = @clock
        flow.packets[direction] += 1
        flow.bytes[direction] += packet.original_length
        flow.closed_ns = @clock if transport && transport[:flags] && transport[:flags] & 4 != 0
        @entries[key] = flow
        [flow, direction]
      end
      # @rbs (Integer now_ns) -> void
      def advance(now_ns)
        @clock = [@clock, now_ns].max
        expire(@clock) if @clock >= @next_sweep
      end
      # @rbs (Integer now_ns) -> void
      def expire(now_ns)
        @next_sweep = now_ns + 1_000_000_000
        @entries.delete_if do |_key, flow|
          timeout = flow.closed? ? 10 : flow.key[0] == :tcp ? 120 : 30
          stale = now_ns - flow.last_ns >= timeout * 1_000_000_000
          if stale
            discard(flow)
            @expired += 1
          end
          stale
        end
      end
      # @rbs () -> Flow?
      def evict
        pair = @entries.shift
        return nil unless pair
        @evicted += 1
        discard(pair[1])
        pair[1]
      end
      # @rbs (Flow flow) -> void
      def discard(flow)
        @bytes -= flow.accounted_bytes
        @tcp_bytes -= flow.accounted_bytes - Flow::BASE_BYTES if flow.key[0] == :tcp
        @on_remove&.call(flow)
      end
      # @rbs (Flow flow) -> void
      def account(flow)
        size = flow.bytesize
        delta = size - flow.accounted_bytes
        @bytes += delta
        @tcp_bytes += delta if flow.key[0] == :tcp
        flow.accounted_bytes = size
      end
      # @rbs () -> Integer
      def size = @entries.size
      # @rbs () -> Array[Flow]
      def values = @entries.values
      # @rbs () -> Integer
      def bytesize = @bytes
      # @rbs () -> Integer
      def tcp_bytesize = @tcp_bytes
    end
  end
end
