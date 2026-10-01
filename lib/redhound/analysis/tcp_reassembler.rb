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
          flow.applications[direction] = klass.new(registry: @registry, max_bytes: @stream_bytes) if klass && klass <= StreamDissector
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
        elsif stream.fin
          attach(packet, application.on_close(flow, direction)) if application
          flow.closed_ns ||= packet.timestamp_ns if flow.streams.compact.size == 2 && flow.streams.compact.all?(&:fin)
        end
      end
      # @rbs (Flow flow, Integer direction, TcpStream stream, untyped application, Packet? packet) -> void
      def deliver(flow, direction, stream, application, packet)
        stream.deliveries.each do |data, origin|
          unless data
            application&.on_gap(flow, direction, origin)
            next
          end
          @follow&.write(flow, direction, data)
          layers = if application
                     begin
                       application.on_data(flow, direction, data, origin)
                     rescue StandardError => error
                       raise if ENV['REDHOUND_STRICT'] == '1'
                       application.on_gap(flow, direction, data.bytesize)
                       [Layer.new(application.class.protocol_id, 0, 0, 0).diagnose(:error, :dissector_bug, "#{error.class}: #{error.message}")]
                     end
                   else
                     Array.new
                   end #: Array[Layer]
          attach(packet, layers) if packet
        end
      ensure
        stream.clear_deliveries
      end
      # @rbs (Packet packet, Array[Layer] layers) -> void
      def attach(packet, layers)
        layers.each do |layer|
          layer.add(:reassembled_in, 'tcp.reassembled_in', packet.number)
          packet.layers << layer
        end
      end
      # @rbs (Flow flow, ?Packet? packet) -> void
      def finish_flow(flow, packet = nil)
        flow.streams.each_with_index do |stream, direction|
          next unless stream
          application = flow.applications[direction]
          while stream.pending?
            stream.flush_gap
            packet&.[](:tcp)&.diagnose(:warning, :reassembly_gap) unless stream.gap_lengths.empty?
            deliver(flow, direction, stream, application, packet)
          end
          attach(packet, application.on_close(flow, direction)) if application && packet
        end
        flow.closed_ns ||= packet ? packet.timestamp_ns : flow.last_ns
      end
      # @rbs (FlowTable flows, Packet packet) -> void
      def enforce_limit(flows, packet)
        while flows.tcp_bytesize > @max_bytes
          flow = flows.evict
          break unless flow
          packet.layers.last.diagnose(:warning, :reassembly_gap, 'TCP reassembly memory limit exceeded')
        end
      end
    end
  end
end
