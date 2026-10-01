# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Ipv6 < Dissector
      protocol :ipv6, name: 'Internet Protocol v6', short: 'IP6'
      dissects_on 'ethertype', 0x86dd
      dissects_on 'ip.proto', 41
      header do
        bits 32 do
          bit :version, 'ipv6.version', 4
          bit :tclass, 'ipv6.tclass', 8
          bit :flow, 'ipv6.flow', 20, format: :hex
        end
        uint16 :plen, 'ipv6.plen'
        uint8 :nxt, 'ipv6.nxt'
        uint8 :hlim, 'ipv6.hlim'
        ipv6 :src, 'ipv6.src'
        ipv6 :dst, 'ipv6.dst'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        layer.diagnose(:error, :malformed, 'IPv6 version is not 6') if layer[:version] != 6
        layer.payload_end = layer.offset + 40 + layer[:plen]
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = ctx.registry.lookup('ip.proto', layer[:nxt])
    end

    # @api private
    class Ipv6Ext < Dissector
      protocol :ipv6_ext, name: 'IPv6 extension', short: 'IP6 EXT'
      dissects_on 'ip.proto', 0, 43, 44, 60, 51
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        ctx.extension_count += 1
        return layer.diagnose(:error, :malformed, 'more than 16 IPv6 extensions') if ctx.extension_count > 16
        parent = ctx.layers.last
        type = parent.protocol == :ipv6 ? parent[:nxt] : parent[:next]
        cursor = ctx.cursor
        nxt = cursor.u8(0)
        layer.add(:next, 'ipv6.nxt', nxt, length: 1)
        layer.add(:type, 'ipv6.extension.type', type)
        length = type == 44 ? 8 : type == 51 ? (cursor.u8(1) + 2) * 4 : (cursor.u8(1) + 1) * 8
        cursor.check(0, length)
        if type == 44
          flags = cursor.u16(2)
          layer.add(:fragment_offset, 'ipv6.fragment.offset', flags & 0xfff8, offset: 2, length: 2)
          layer.add(:more, 'ipv6.fragment.more', flags & 1)
          layer.add(:identification, 'ipv6.fragment.id', cursor.u32(4), offset: 4, length: 4)
        end
        layer.header_length = length
        layer.payload_offset += length
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer)
        return nil if layer[:fragment_offset] && layer[:fragment_offset] != 0
        ctx.registry.lookup('ip.proto', layer[:next])
      end
    end
  end
end
