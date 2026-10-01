# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Gre < Dissector
      protocol :gre, name: 'Generic Routing Encapsulation', short: 'GRE'
      dissects_on 'ip.proto', 47
      header do
        uint16 :flags, 'gre.flags', format: :hex
        uint16 :type, 'gre.proto', format: :hex
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        flags, len = layer[:flags], 4
        return layer.diagnose(:error, :malformed, 'unsupported GRE version or routing') unless (flags & 0x4007).zero?
        len += 4 if flags & 0x8000 != 0
        if flags & 0x2000 != 0
          layer.add(:key, 'gre.key', ctx.cursor.u32(len), offset: len, length: 4)
          len += 4
        end
        len += 4 if flags & 0x1000 != 0
        ctx.cursor.check(0, len)
        layer.header_length, layer.payload_offset = len, layer.offset + len
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = layer[:type] == 0x6558 ? Ethernet : ctx.registry.lookup('ethertype', layer[:type])
    end
    # @api private
    class Vxlan < Dissector
      protocol :vxlan, name: 'Virtual eXtensible LAN', short: 'VXLAN'
      dissects_on 'udp.port', 4789
      header do
        uint32 :flags, 'vxlan.flags', format: :hex
        uint32 :vni_word, 'vxlan.vni_word'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        layer.add(:vni, 'vxlan.vni', layer[:vni_word] >> 8, offset: 4, length: 3)
        layer.diagnose(:error, :malformed, 'VXLAN I flag is unset') if layer[:flags] & 0x08000000 == 0
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = Ethernet
    end
  end
end
