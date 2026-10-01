# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Ethernet < Dissector
      protocol :eth, name: 'Ethernet', short: 'ETH'
      dissects_on 'linktype', 1
      header do
        mac :dst, 'eth.dst'
        mac :src, 'eth.src'
        uint16 :type, 'eth.type', format: :hex
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        layer.payload_end = layer.payload_offset + layer[:type] if layer[:type] <= 1500
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = layer[:type] <= 1500 ? Llc : ctx.registry.lookup('ethertype', layer[:type])
    end
  end
end
