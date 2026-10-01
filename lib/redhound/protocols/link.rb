# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Sll < Dissector
      protocol :sll, name: 'Linux cooked capture', short: 'SLL'
      dissects_on 'linktype', 113
      header do
        uint16 :pkttype, 'sll.pkttype'
        uint16 :hatype, 'sll.hatype'
        uint16 :halen, 'sll.halen'
        uint64 :address, 'sll.src'
        uint16 :type, 'sll.etype'
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = ctx.registry.lookup('ethertype', layer[:type])
    end
    # @api private
    class Sll2 < Dissector
      protocol :sll2, name: 'Linux cooked capture v2', short: 'SLL2'
      dissects_on 'linktype', 276
      header do
        uint16 :type, 'sll.etype'
        uint16 :reserved, 'sll.reserved'
        uint32 :ifindex, 'sll.ifindex'
        uint16 :hatype, 'sll.hatype'
        uint8 :pkttype, 'sll.pkttype'
        uint8 :halen, 'sll.halen'
        uint64 :address, 'sll.src'
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = ctx.registry.lookup('ethertype', layer[:type])
    end
    # @api private
    class Null < Dissector
      protocol :null, name: 'BSD loopback', short: 'NULL'
      dissects_on 'linktype', 0, 108
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        bytes = ctx.cursor.bytes(0, 4)
        family = bytes.unpack1(ctx.packet.linktype == 108 ? 'N' : 'L')
        family = bytes.unpack1('N') if family > 255
        layer.add(:family, 'null.family', family, length: 4)
        layer.header_length = 4
        layer.payload_offset += 4
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer)
        return Ipv4 if layer[:family] == 2
        return Ipv6 if [10, 24, 28, 30].include?(layer[:family])
        nil
      end
    end
    # @api private
    class Raw < Dissector
      protocol :raw, name: 'Raw IP', short: 'RAW'
      dissects_on 'linktype', 101, 228, 229
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer)
        case ctx.cursor.u8(0) >> 4
        when 4 then Ipv4
        when 6 then Ipv6
        end
      end
    end
  end
end
