# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Analysis
    # @api private
    class TcpReassembler
      # @rbs (?registry: Registry, ?max_bytes: Integer, ?stream_bytes: Integer, ?protocol_streams: bool, ?follow: untyped) -> void
      def initialize(registry: Registry.default, max_bytes: 64 << 20, stream_bytes: 1 << 20, protocol_streams: true, follow: nil)
        @registry, @max_bytes, @stream_bytes, @protocol_streams, @follow = registry, max_bytes, stream_bytes, protocol_streams, follow
      end
      # @rbs (Packet packet, Flow flow, Integer direction) -> void
      def update(packet, flow, direction)
        layer = packet.layers.reverse.find { |item| item.protocol == :tcp && !item.embedded }
        return unless layer && !layer.error? && layer[:seq] && layer[:flags]
        stream = flow.streams[direction] ||= TcpStream.new(max_bytes: @stream_bytes)
        application = flow.applications[direction]
        if !application && @protocol_streams
          klass = @registry.by_port('tcp.port', layer[:srcport], layer[:dstport])
          unless klass
            recognized = packet.layers.find { |item| (candidate = @registry.protocols[item.protocol]) && candidate <= StreamDissector }
            klass = recognized ? @registry.protocols[recognized.protocol] : flow.applications[1 - direction]&.class
          end
          flow.applications[direction] = create_application(klass, flow, direction, layer) if klass && klass <= StreamDissector
          application = flow.applications[direction]
        end
        TcpAnalysis.update(flow, direction, stream, layer, packet.timestamp_ns)
        flags = layer[:flags]
        data = packet.data.byteslice(layer.payload_offset, layer.payload_end - layer.payload_offset) #: String
        stream.push(layer[:seq], data, syn: flags & 2 != 0, fin: flags & 1 != 0, frame: packet.number)
        # Packet-local application parsing cannot frame a multi-segment PDU.
        if application
          index = packet.layers.index(layer) #: Integer
          packet.layers.slice!(index + 1, packet.layers.length)
        end
        stream.diagnostics.uniq.each do |code|
          if %i[retransmission out_of_order lost_segment].include?(code)
            TcpAnalysis.flag(layer, code) unless layer.field_value('tcp.analysis.keep_alive')
          else
            layer.diagnose(:warning, code)
          end
        end
        deliver(flow, direction, stream, application, packet)
        if flags & 4 != 0
          finish_flow(flow, packet)
        elsif flow.streams.compact.size == 2 && flow.streams.compact.all?(&:fin_seen?)
          finish_flow(flow, packet)
        elsif stream.fin
          attach(packet, invoke(flow, direction, application, :on_close)) if application
          flow.closed_ns ||= packet.timestamp_ns if flow.streams.compact.size == 2 && flow.streams.compact.all?(&:fin)
        end
      end
      # @rbs (Flow flow, Integer direction, TcpStream stream, untyped application, Packet? packet) -> Array[Layer]
      def deliver(flow, direction, stream, application, packet)
        completed = [] #: Array[Layer]
        stream.deliveries.each do |data, origin|
          unless data
            gap = Layer.new(:tcp, 0, 0, 0).diagnose(:warning, :reassembly_gap, "#{origin} TCP bytes missing")
            packet&.[](:tcp)&.diagnose(:warning, :reassembly_gap, gap.diagnostics.first.message)
            completed << gap unless packet
            flow.probes[direction].clear
            flow.probe_disabled[direction] = false
            application = flow.applications[direction]
            layers = application ? invoke(flow, direction, application, :on_gap, origin) : Array.new #: Array[Layer]
            completed.concat(layers)
            attach(packet, layers) if packet
            next
          end
          @follow&.write(flow, direction, data)
          layers = application_data(flow, direction, data, origin, packet)
          attach(packet, layers) if packet
          completed.concat(layers)
        end
        completed
      ensure
        stream.clear_deliveries
      end
      # @rbs (Flow flow, Integer direction, String data, Integer origin, Packet? packet) -> Array[Layer]
      def application_data(flow, direction, data, origin, packet)
        application = flow.applications[direction]
        probe = flow.probes[direction]
        unless application
          return [] unless @protocol_streams && !flow.probe_disabled[direction]
          sample = (probe.map(&:first).join + data.byteslice(0, 128)).byteslice(0, 128) #: String
          ctx = Context.new(Packet.new(sample), registry: @registry)
          ctx.layers << Layer.new(:tcp, 0, 0, sample.bytesize)
          klass = @registry.heuristic(:tcp, ctx, ctx.cursor)
          if klass && klass <= StreamDissector
            diagnostic_layer = packet&.[](:tcp) || Layer.new(:tcp, 0, 0, 0)
            application = flow.applications[direction] = create_application(klass, flow, direction, diagnostic_layer)
            return packet ? [] : [diagnostic_layer] unless application
            if packet
              position = packet.layers.index { |layer| layer.protocol == :tcp && !layer.embedded }
              packet.layers.slice!(position + 1, packet.layers.size) if position
            end
          else
            if sample.bytesize < 128 && probe.sum { |bytes, _frame| bytes.bytesize * 2 + 128 } + data.bytesize * 2 + 128 <= @stream_bytes
              probe << [data.dup, origin]
            else
              probe.clear
              flow.probe_disabled[direction] = true
            end
            return []
          end
        end
        chunks = probe + [[data, origin]]
        probe.clear
        chunks.flat_map { |bytes, frame| invoke(flow, direction, application, :on_data, bytes, frame) }
      rescue StandardError => error
        [application_error(flow, direction, :tcp, error)]
      end
      # @rbs (untyped klass, Flow flow, Integer direction, Layer layer) -> untyped
      def create_application(klass, flow, direction, layer)
        klass.new(registry: @registry, max_bytes: @stream_bytes)
      rescue StandardError => error
        layer.diagnostics.concat(application_error(flow, direction, klass.protocol_id, error).diagnostics)
        nil
      end
      # @rbs (Flow flow, Integer direction, untyped application, Symbol method, *untyped arguments) -> Array[Layer]
      def invoke(flow, direction, application, method, *arguments)
        layers = application.public_send(method, flow, direction, *arguments)
        raise TypeError, 'stream callback must return an array of Layers' unless layers.is_a?(Array) && layers.all? { |layer| layer.is_a?(Layer) }
        layers
      rescue StandardError => error
        [application_error(flow, direction, application.class.protocol_id, error)]
      end
      # @rbs (Flow flow, Integer direction, Symbol protocol, StandardError error) -> Layer
      def application_error(flow, direction, protocol, error)
        raise error if ENV['REDHOUND_STRICT'] == '1'
        flow.applications[direction] = nil
        flow.probes[direction].clear
        flow.probe_disabled[direction] = true
        Layer.new(protocol, 0, 0, 0).diagnose(:error, :dissector_bug, "#{error.class}: #{error.message}")
      end
      # @rbs (Packet packet, Array[Layer] layers) -> void
      def attach(packet, layers)
        layers.each do |layer|
          layer.add(:reassembled_in, 'tcp.reassembled_in', packet.number)
          packet.layers << layer
        end
      end
      # @rbs (Flow flow, ?Packet? packet) -> Array[Layer]
      def finish_flow(flow, packet = nil)
        completed = [] #: Array[Layer]
        flow.streams.each_with_index do |stream, direction|
          next unless stream
          application = flow.applications[direction]
          while stream.pending?
            stream.flush_gap
            completed.concat(deliver(flow, direction, stream, application, packet))
          end
          application = flow.applications[direction]
          if application
            layers = invoke(flow, direction, application, :on_close)
            attach(packet, layers) if packet
            completed.concat(layers)
          end
          stream.release
        end
        flow.http_methods.each(&:clear)
        flow.probes.each(&:clear)
        flow.closed_ns ||= packet ? packet.timestamp_ns : flow.last_ns
        completed
      end
      # @rbs (FlowTable flows, Packet packet) -> void
      def enforce_limit(flows, packet)
        while flows.tcp_bytesize > @max_bytes
          flow = flows.evict(:tcp)
          break unless flow
          packet.layers.last.diagnose(:warning, :reassembly_gap, 'TCP reassembly memory limit exceeded')
        end
      end
    end
  end
end
