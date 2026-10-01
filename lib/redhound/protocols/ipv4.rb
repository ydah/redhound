# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Ipv4 < Dissector
      protocol :ipv4, name: 'Internet Protocol v4', short: 'IP'
      dissects_on 'ethertype', 0x0800
      dissects_on 'ip.proto', 4
      header do
        bits 8 do
          bit :version, 'ip.version', 4
          bit :hdr_len, 'ip.hdr_len', 4, scale: 4
        end
        bits 8 do
          bit :dscp, 'ip.dsfield.dscp', 6
          bit :ecn, 'ip.dsfield.ecn', 2
        end
        uint16 :len, 'ip.len'
        uint16 :id, 'ip.id', format: :hex
        bits 16 do
          bit :reserved, 'ip.flags.rb', 1
          bit :df, 'ip.flags.df', 1
          bit :mf, 'ip.flags.mf', 1
          bit :frag_offset, 'ip.frag_offset', 13, scale: 8
        end
        uint8 :ttl, 'ip.ttl'
        uint8 :proto, 'ip.proto'
        uint16 :checksum, 'ip.checksum', format: :hex
        ipv4 :src, 'ip.src'
        ipv4 :dst, 'ip.dst'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        hlen = layer[:hdr_len]
        if layer[:version] != 4 || hlen < 20 || layer[:len] < hlen
          layer.diagnose(:error, :bad_length, 'invalid IPv4 version or length')
          return
        end
        ctx.cursor.check(0, hlen)
        layer.header_length = hlen
        layer.payload_offset = layer.offset + hlen
        layer.payload_end = layer.offset + layer[:len]
        layer.add(:options, 'ip.options', ctx.cursor.bytes(20, hlen - 20), type: :bytes, offset: 20, length: hlen - 20) if hlen > 20
        Checksum.verify(ctx, layer, ctx.cursor.bytes(0, hlen))
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer)
        return nil unless layer[:frag_offset].zero?
        ctx.registry.lookup('ip.proto', layer[:proto])
      end
    end
  end
end
