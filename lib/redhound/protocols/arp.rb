# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Arp < Dissector
      protocol :arp, name: 'Address Resolution Protocol', short: 'ARP'
      dissects_on 'ethertype', 0x0806
      header do
        uint16 :hwtype, 'arp.hw.type'
        uint16 :protype, 'arp.proto.type'
        uint8 :hwlen, 'arp.hw.size'
        uint8 :prolen, 'arp.proto.size'
        uint16 :opcode, 'arp.opcode'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        hlen, plen = layer[:hwlen], layer[:prolen]
        cursor = ctx.cursor
        cursor.check(8, (hlen + plen) * 2)
        if hlen == 6 && plen == 4 && layer[:protype] == 0x0800
          layer.add(:sha, 'arp.src.hw_mac', cursor.bytes(8, 6), type: :mac, offset: 8, length: 6)
          layer.add(:spa, 'arp.src.proto_ipv4', cursor.u32(14), type: :ipv4, offset: 14, length: 4)
          layer.add(:tha, 'arp.dst.hw_mac', cursor.bytes(18, 6), type: :mac, offset: 18, length: 6)
          layer.add(:tpa, 'arp.dst.proto_ipv4', cursor.u32(24), type: :ipv4, offset: 24, length: 4)
        end
        layer.header_length = 8 + 2 * (hlen + plen)
        layer.payload_end = layer.payload_offset = layer.offset + layer.header_length
      end
      # @rbs (Layer layer) -> String
      def summary(layer)
        layer[:opcode] == 1 ? "ARP, Request who-has #{layer.display(:tpa)} tell #{layer.display(:spa)}" :
                             "ARP, Reply #{layer.display(:spa)} is-at #{layer.display(:sha)}"
      end
    end
  end
end
