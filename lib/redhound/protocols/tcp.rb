# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Tcp < Dissector
      FLAGS = { 0x80 => 'C', 0x40 => 'E', 0x20 => 'U', 0x10 => '.', 8 => 'P', 4 => 'R', 2 => 'S', 1 => 'F' }.freeze
      FLAG_FIELDS = %w[fin syn reset push ack urg ecn cwr].each_with_index.map do |name, bit|
        [FieldDefinition.new(:"flag_#{name}", "tcp.flags.#{name}", :boolean, 13, 1, 0, nil, nil, 1, nil, nil), 1 << bit]
      end.freeze
      protocol :tcp, name: 'Transmission Control Protocol', short: 'TCP'
      dissects_on 'ip.proto', 6
      header do
        uint16 :srcport, 'tcp.srcport'
        uint16 :dstport, 'tcp.dstport'
        uint32 :seq, 'tcp.seq'
        uint32 :ack, 'tcp.ack'
        bits 16 do
          bit :hdr_len, 'tcp.hdr_len', 4, scale: 4
          bit :reserved, 'tcp.reserved', 3
          bit :flags, 'tcp.flags', 9, format: :hex
        end
        uint16 :window, 'tcp.window_size_value'
        uint16 :checksum, 'tcp.checksum', format: :hex
        uint16 :urgent, 'tcp.urgent_pointer'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        hlen = layer[:hdr_len]
        return layer.diagnose(:error, :bad_length, 'TCP data offset is less than 20') if hlen < 20
        ctx.cursor.check(0, hlen)
        layer.header_length, layer.payload_offset = hlen, layer.offset + hlen
        FLAG_FIELDS.each do |definition, mask|
          layer.definitions << definition
          layer.values[definition.key] = (layer[:flags] & mask) != 0
        end
        options(ctx.cursor, layer, hlen)
        layer.add(:length, 'tcp.len', ctx.cursor.remaining - hlen)
        Checksum.verify(ctx, layer, ctx.cursor.bytes(0, ctx.cursor.remaining), 6)
      end
      # @rbs (Cursor cursor, Layer layer, Integer hlen) -> void
      def options(cursor, layer, hlen)
        pos = 20
        while pos < hlen
          kind = cursor.u8(pos)
          break if kind.zero?
          if kind == 1
            pos += 1
            next
          end
          return layer.diagnose(:error, :bad_length, 'truncated TCP option') if pos + 2 > hlen
          len = cursor.u8(pos + 1)
          return layer.diagnose(:error, :bad_length, 'invalid TCP option length') if len < 2 || pos + len > hlen
          valid = case kind
                  when 2 then len == 4
                  when 3 then len == 3
                  when 4 then len == 2
                  when 5 then len >= 10 && (len - 2) % 8 == 0
                  when 8 then len == 10
                  when 34 then len == 2 || len.between?(6, 18)
                  else true
                  end
          return layer.diagnose(:error, :bad_length, "invalid TCP option #{kind} length") unless valid
          case kind
          when 2 then layer.add(:mss, 'tcp.options.mss_val', cursor.u16(pos + 2), offset: pos + 2, length: 2)
          when 3 then layer.add(:wscale, 'tcp.options.wscale.shift', cursor.u8(pos + 2), offset: pos + 2, length: 1)
          when 4 then layer.add(:sack_permitted, 'tcp.options.sack_perm', true, type: :boolean, offset: pos, length: 2)
          when 5 then layer.add(:sack, 'tcp.options.sack', cursor.bytes(pos + 2, len - 2), type: :bytes, offset: pos + 2, length: len - 2)
          when 8
            layer.add(:tsval, 'tcp.options.timestamp.tsval', cursor.u32(pos + 2), offset: pos + 2, length: 4)
            layer.add(:tsecr, 'tcp.options.timestamp.tsecr', cursor.u32(pos + 6), offset: pos + 6, length: 4)
          when 34 then layer.add(:tfo, 'tcp.options.tfo.cookie', cursor.bytes(pos + 2, len - 2), type: :bytes, offset: pos + 2, length: len - 2)
          end
          pos += len
        end
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = ctx.registry.by_port('tcp.port', layer[:srcport], layer[:dstport])
      # @rbs (Layer layer) -> String
      def summary(layer)
        flags = FLAGS.filter_map { |bit, name| name if layer[:flags] & bit != 0 }.join
        "TCP [#{flags}], seq #{layer[:seq]}, ack #{layer[:ack]}, win #{layer[:window]}, length #{layer[:length]}"
      end
    end
  end
end
