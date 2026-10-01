# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Udp < Dissector
      protocol :udp, name: 'User Datagram Protocol', short: 'UDP'
      dissects_on 'ip.proto', 17
      header do
        uint16 :srcport, 'udp.srcport'
        uint16 :dstport, 'udp.dstport'
        uint16 :length, 'udp.length'
        uint16 :checksum, 'udp.checksum', format: :hex
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        len = layer[:length]
        return layer.diagnose(:error, :bad_length, 'UDP length is less than 8') if len < 8
        layer.payload_end = layer.offset + len
        return unless len <= ctx.cursor.remaining
        return if layer[:checksum].zero? && ctx.network&.protocol == :ipv4
        Checksum.verify(ctx, layer, ctx.cursor.bytes(0, len), 17)
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = ctx.registry.by_port('udp.port', layer[:srcport], layer[:dstport])
      # @rbs (Layer layer) -> String
      def summary(layer) = "UDP, length #{layer[:length] - 8}"
    end
  end
end
