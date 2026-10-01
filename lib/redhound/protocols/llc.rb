# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Llc < Dissector
      protocol :llc, name: 'Logical Link Control', short: 'LLC'
      header do
        uint8 :dsap, 'llc.dsap'
        uint8 :ssap, 'llc.ssap'
        uint8 :control, 'llc.control'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        if layer[:control] & 3 != 3
          layer.values[:control] |= ctx.cursor.u8(3) << 8
          layer.definitions[2] = layer.definitions[2].with(type: :uint16, length: 2)
          layer.header_length = 4
          layer.payload_offset = layer.offset + 4
          return
        end
        return unless layer[:dsap] == 0xaa && layer[:ssap] == 0xaa && layer[:control] == 3
        layer.add(:oui, 'llc.oui', ctx.cursor.bytes(3, 3), type: :bytes, offset: 3, length: 3)
        layer.add(:type, 'llc.pid', ctx.cursor.u16(6), offset: 6, length: 2, format: :hex)
        layer.header_length = 8
        layer.payload_offset = layer.offset + 8
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer)
        return ctx.registry.lookup('ethertype', layer[:type]) if layer[:oui] == "\0\0\0".b
        ctx.registry.lookup('llc.dsap', layer[:dsap])
      end
    end
  end
end
