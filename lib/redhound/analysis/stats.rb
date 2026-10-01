# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Analysis
    # @api private
    module Stats
      # @api private
      class Table
        attr_reader :evicted
        # @rbs (?max_rows: Integer) -> void
        def initialize(max_rows: 100_000)
          @max_rows, @evicted = max_rows, 0
          @rows = {} #: Hash[untyped, untyped]
        end
        # @rbs (untyped key) { () -> untyped } -> untyped
        def row(key)
          item = @rows.delete(key)
          unless item
            if @rows.size >= @max_rows
              @rows.shift
              @evicted += 1
            end
            item = yield
          end
          @rows[key] = item
          item
        end
        # @rbs () -> Integer
        def bytesize = @rows.size * 1024
        # @rbs () -> void
        def evict
          @evicted += 1 if @rows.shift
        end
        # @rbs (untyped io) -> void
        def format(io)
          result = to_h
          io.puts("#{result[:kind]}#{result[:type] ? ",#{result[:type]}" : ''}")
          result[:rows].each { |item| io.puts(item.map { |name, value| "#{name}=#{value.is_a?(Array) ? value.join(':') : value}" }.join(' ')) }
          io.puts("#{result[:omitted_intervals]} earlier IO intervals omitted") if result[:omitted_intervals] && result[:omitted_intervals].positive?
          io.puts("#{@evicted} statistics rows evicted") if @evicted.positive?
        end
        # @rbs () -> Hash[Symbol, untyped]
        def to_h = { kind: :stats, rows: @rows.values }
      end

      # @api private
      class Io < Table
        # @rbs ((Integer | Float) seconds, ?max_rows: Integer) -> void
        def initialize(seconds, max_rows: 100_000)
          super(max_rows: max_rows)
          @interval_ns = (seconds * 1_000_000_000).to_i
          raise ArgumentError, 'statistics interval must be positive' unless @interval_ns.positive?
          @start_ns = nil # @rbs Integer?
        end
        # @rbs (Packet packet) -> void
        def update(packet)
          @start_ns ||= packet.timestamp_ns
          start = @start_ns #: Integer
          interval = [(packet.timestamp_ns - start) / @interval_ns, 0].max
          item = row(interval) { interval_row(interval) }
          item[:packets] += 1
          item[:bytes] += packet.original_length
        end
        # @rbs () -> Hash[Symbol, untyped]
        def to_h
          return { kind: :io, interval_ns: @interval_ns, rows: [] } if @rows.empty?
          last = @rows.keys.max #: Integer
          first = [@rows.keys.min, last - @max_rows + 1].max #: Integer
          rows = (first..last).map { |interval| @rows[interval] || interval_row(interval) }
          { kind: :io, interval_ns: @interval_ns, omitted_intervals: first, rows: rows }
        end
        # @rbs (Integer interval) -> Hash[Symbol, Integer]
        def interval_row(interval)
          start = @start_ns || 0
          { interval: interval, start_ns: start + interval * @interval_ns, end_ns: start + (interval + 1) * @interval_ns, packets: 0, bytes: 0 }
        end
      end

      # @api private
      class Conversations < Table
        # @rbs (Symbol type, ?max_rows: Integer) -> void
        def initialize(type, max_rows: 100_000)
          super(max_rows: max_rows)
          @type = type
        end
        # @rbs (Packet packet) -> void
        def update(packet)
          result = FlowKey.from(packet, @type)
          return unless result
          key, direction = result
          item = row(key) do
            { addr_a: key[1], port_a: key[2], addr_b: key[3], port_b: key[4],
              packets_ab: 0, packets_ba: 0, bytes_ab: 0, bytes_ba: 0,
              start_ns: packet.timestamp_ns, end_ns: packet.timestamp_ns, duration_ns: 0 }
          end
          suffix = direction.zero? ? 'ab' : 'ba'
          item["packets_#{suffix}".to_sym] += 1
          item["bytes_#{suffix}".to_sym] += packet.original_length
          item[:start_ns] = [item[:start_ns], packet.timestamp_ns].min
          item[:end_ns] = [item[:end_ns], packet.timestamp_ns].max
          item[:duration_ns] = item[:end_ns] - item[:start_ns]
        end
        # @rbs () -> Hash[Symbol, untyped]
        def to_h = { kind: :conv, type: @type, rows: @rows.values }
      end

      # @api private
      class Endpoints < Table
        # @rbs (Symbol type, ?max_rows: Integer) -> void
        def initialize(type, max_rows: 100_000)
          super(max_rows: max_rows)
          @type = type
        end
        # @rbs (Packet packet) -> void
        def update(packet)
          result = FlowKey.from(packet, @type)
          return unless result
          key, direction = result
          endpoints = [[key[1], key[2]], [key[3], key[4]]]
          endpoints.each_with_index do |endpoint, index|
            item = row(endpoint) { { address: endpoint[0], port: endpoint[1], packets_tx: 0, packets_rx: 0, bytes_tx: 0, bytes_rx: 0 } }
            suffix = index == direction ? 'tx' : 'rx'
            item["packets_#{suffix}".to_sym] += 1
            item["bytes_#{suffix}".to_sym] += packet.original_length
          end
        end
        # @rbs () -> Hash[Symbol, untyped]
        def to_h = { kind: :endpoints, type: @type, rows: @rows.values }
      end

      # @api private
      class Hierarchy < Table
        # @rbs (Packet packet) -> void
        def update(packet)
          path = [] #: Array[Symbol]
          packet.layers.reject(&:embedded).each do |layer|
            path << layer.protocol
            item = row(path.dup) { { path: path.dup, packets: 0, bytes: 0 } }
            item[:packets] += 1
            item[:bytes] += packet.original_length
          end
        end
        # @rbs () -> Hash[Symbol, untyped]
        def to_h = { kind: :phs, rows: @rows.values }
      end
    end
  end
end
