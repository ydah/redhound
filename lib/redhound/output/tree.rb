# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Output
    # @api private
    class Tree
      # @rbs (Packet packet, untyped io) -> void
      def format(packet, io)
        interface = packet.interface ? safe([packet.interface.name, packet.direction&.to_s&.capitalize].compact.join(' ')) + ', ' : ''
        io.write("Frame #{packet.number}: #{packet.original_length} bytes on wire, #{packet.caplen} captured, #{interface}#{packet.time.utc.strftime('%Y-%m-%d %H:%M:%S')}.#{Kernel.format('%09d', packet.time.nsec)}\n")
        packet.layers.each_with_index do |layer, depth|
          klass = Registry.default.protocols[layer.protocol]
          indent = '   ' * depth
          io.write("#{indent}└─ #{klass&.protocol_name || layer.protocol}#{layer.embedded ? ' (embedded)' : ''}\n")
          layer.fields.each { |field| io.write("#{indent}   #{field.name}: #{field.display}\n") }
          layer.diagnostics.each { |d| io.write("#{indent}   [#{d.severity}] #{d.code}: #{safe(d.message)}\n") }
        end
      end
      # @rbs (String text) -> String
      def safe(text) = text.b.gsub(/[^\x20-\x7e]/n) { |c| Kernel.format('\\x%02x', c.getbyte(0)) }
    end
  end
end
