# rbs_inline: enabled
# frozen_string_literal: true

require_relative 'util/seq'
require_relative 'stream_dissector'
require_relative 'analysis/flow_key'
require_relative 'analysis/tcp_stream'
require_relative 'analysis/flow_table'
require_relative 'analysis/ip_reassembler'
require_relative 'analysis/tcp_analysis'
require_relative 'analysis/tcp_reassembler'
require_relative 'analysis/stats'
require_relative 'output/follow'

module Redhound
  # @api private
  module Analysis
    # @api private
    class Session
      attr_reader :flows, :ip_reassembler, :tcp_reassembler, :statistics
      # @rbs (?stats: Array[String], ?follow: String?, ?registry: Registry, ?max_state_bytes: Integer, ?max_flows: Integer, ?ip_bytes: Integer, ?tcp_bytes: Integer, ?stream_bytes: Integer, ?protocol_streams: bool) -> void
      def initialize(stats: [], follow: nil, registry: Registry.default, max_state_bytes: 256 << 20, max_flows: 100_000,
                     ip_bytes: 16 << 20, tcp_bytes: 64 << 20, stream_bytes: 1 << 20, protocol_streams: true)
        raise ArgumentError, 'state limit must be positive' unless max_state_bytes.positive?
        @max_state_bytes, @finished = max_state_bytes, false
        @flows = FlowTable.new(max_flows: max_flows)
        @ip_reassembler = IpReassembler.new(max_bytes: [ip_bytes, max_state_bytes].min)
        @follow = follow ? Output::Follow.new(follow) : nil
        @tcp_reassembler = TcpReassembler.new(registry: registry, max_bytes: [tcp_bytes, max_state_bytes].min,
                                             stream_bytes: stream_bytes, protocol_streams: protocol_streams, follow: @follow)
        @removed_gaps, @removed_incomplete, @removed_bugs = 0, 0, 0
        @flows.on_remove = lambda do |flow|
          @tcp_reassembler.finish_flow(flow).each do |layer|
            layer.diagnostics.each do |diagnostic|
              @removed_gaps += 1 if diagnostic.code == :reassembly_gap
              @removed_incomplete += 1 if diagnostic.code == :truncated
              @removed_bugs += 1 if diagnostic.code == :dissector_bug
            end
          end
        end
        specs = stats.uniq
        raise ConfigurationError, 'too many statistics specifications (maximum 64)' if specs.size > 64
        row_limit = [100_000, [((128 << 20) / [specs.size, 1].max) / 1024, 1].max].min
        @statistics = specs.map { |spec| statistic(spec, row_limit) }
      end
      # @rbs (String specification, Integer max_rows) -> untyped
      def statistic(specification, max_rows)
        kind, argument = specification.split(',', 2)
        case kind
        when 'io'
          raise ConfigurationError, 'io statistics requires an interval of at least one nanosecond' unless argument && argument.match?(/\A(?:\d+(?:\.\d*)?|\.\d+)\z/) && argument.to_f.finite? && argument.to_f >= 0.000_000_001
          Stats::Io.new(argument.to_f, max_rows: max_rows)
        when 'conv', 'endpoints'
          raise ConfigurationError, 'statistics type must be eth, ip, ipv6, tcp or udp' unless argument && %w[eth ip ipv6 tcp udp].include?(argument)
          klass = kind == 'conv' ? Stats::Conversations : Stats::Endpoints
          klass.new(argument.to_sym, max_rows: max_rows)
        when 'phs'
          raise ConfigurationError, 'phs does not accept an argument' if argument
          Stats::Hierarchy.new(max_rows: max_rows)
        else raise ConfigurationError, "unknown statistics: #{specification}"
        end
      end
      # @rbs (Packet packet) -> void
      def update(packet)
        return if @finished
        @flows.advance(packet.timestamp_ns)
        @ip_reassembler.advance(packet.timestamp_ns)
        fragment = @ip_reassembler.descriptor(packet)
        analyzed = packet
        if fragment
          boundary = packet.layers.index(fragment[1]) #: Integer
          packet.layers.slice!(boundary + 1, packet.layers.length)
          virtual = @ip_reassembler.update(packet)
          if virtual
            packet.meta[:reassembled_from] = virtual.meta[:reassembled_from]
            packet.meta[:reassembled_packet] = virtual
            analyzed = virtual
          else
            @statistics.each { |stat| stat.update(packet) }
            enforce_limit(packet)
            return
          end
        end
        result = @flows.update(analyzed)
        if result
          flow, direction = result
          @tcp_reassembler.update(analyzed, flow, direction) if flow.key[0] == :tcp
          @flows.account(flow)
        end
        if analyzed != packet
          packet.layers.concat(analyzed.layers.reject { |layer| %i[ipv4 ipv6 ipv6_ext].include?(layer.protocol) })
          packet.layers.last.add(:ip_reassembled_from, 'ip.reassembled_from', packet.meta[:reassembled_from])
        end
        @statistics.each { |stat| stat.update(packet) }
        @tcp_reassembler.enforce_limit(@flows, packet)
        enforce_limit(packet)
      end
      # @rbs (Packet packet) -> void
      def enforce_limit(packet)
        while bytesize > @max_state_bytes
          flow = @flows.evict
          unless flow
            statistic = @statistics.max_by(&:bytesize)
            break unless statistic && statistic.bytesize.positive?
            statistic.evict
          end
          packet.layers.last.diagnose(:warning, :state_evicted, 'analysis state memory limit exceeded')
        end
      end
      # @rbs () -> Integer
      def bytesize = @flows.bytesize + @ip_reassembler.bytesize + @statistics.sum(&:bytesize)
      # @rbs (untyped err) -> void
      def snapshot(err)
        @statistics.each { |stat| stat.format(err) }
        err.puts("#{@removed_gaps} TCP reassembly_gap events during flow removal") if @removed_gaps.positive?
        err.puts("#{@removed_incomplete} truncated application PDUs during flow removal") if @removed_incomplete.positive?
        err.puts("#{@removed_bugs} dissector_bug events during flow removal") if @removed_bugs.positive?
        err.puts("#{@flows.evicted} flows evicted; #{@flows.expired} flows expired") if @flows.evicted.positive? || @flows.expired.positive?
        err.puts("#{@ip_reassembler.evicted} fragmented datagrams evicted; #{@ip_reassembler.expired} expired") if @ip_reassembler.evicted.positive? || @ip_reassembler.expired.positive?
      end
      # @rbs (untyped out, untyped err) -> void
      def finish(out, err)
        return if @finished
        @flows.values.each do |flow|
          @tcp_reassembler.finish_flow(flow).each do |layer|
            layer.diagnostics.each do |diagnostic|
              message = diagnostic.message.b.gsub(/[^\x20-\x7e]/n) { |byte| format('\\x%02x', byte.getbyte(0)) }
              err.puts("stream #{flow.id} #{layer.protocol}: #{diagnostic.code}: #{message}")
            end
          end
          @flows.account(flow)
        end
        incomplete = @ip_reassembler.finish
        err.puts("#{incomplete} incomplete IP datagrams: reassembly_gap at EOF") if incomplete.positive?
        @follow&.format(out)
        snapshot(err)
      ensure
        original_error = $!
        @finished = true
        @flows.values.each do |flow|
          flow.streams.compact.each(&:release)
          flow.applications.fill(nil)
          flow.http_methods.each(&:clear)
          flow.probes.each(&:clear)
          flow.closed_ns ||= flow.last_ns
          @flows.account(flow)
        end
        @ip_reassembler.finish
        begin
          @follow&.close
        rescue StandardError
          raise unless original_error
        end
      end
    end
  end
end
