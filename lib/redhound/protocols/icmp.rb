# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Icmp < Dissector
      protocol :icmp, name: 'Internet Control Message Protocol', short: 'ICMP'
      dissects_on 'ip.proto', 1
      header do
        uint8 :type, 'icmp.type'
        uint8 :code, 'icmp.code'
        uint16 :checksum, 'icmp.checksum', format: :hex
        uint16 :ident, 'icmp.ident'
        uint16 :seq, 'icmp.seq'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer) = Checksum.verify(ctx, layer, ctx.cursor.bytes(0, ctx.cursor.remaining))
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer)
        return nil unless [3, 4, 5, 11, 12].include?(layer[:type])
        ctx.embedded = true
        Ipv4
      end
      # @rbs (Layer layer) -> String
      def summary(layer) = "ICMP type #{layer[:type]}, code #{layer[:code]}, id #{layer[:ident]}, seq #{layer[:seq]}"
    end

    # @api private
    class Icmpv6 < Dissector
      protocol :icmpv6, name: 'ICMPv6 / Neighbor Discovery', short: 'ICMP6'
      dissects_on 'ip.proto', 58
      header do
        uint8 :type, 'icmpv6.type'
        uint8 :code, 'icmpv6.code'
        uint16 :checksum, 'icmpv6.checksum'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        cursor, type = ctx.cursor, layer[:type]
        length = case type
                 when 133 then 8
                 when 134 then 16
                 when 135, 136 then 24
                 when 137 then 40
                 else 8
                 end
        cursor.check(0, length)
        if [128, 129].include?(type)
          layer.add(:ident, 'icmpv6.echo.identifier', cursor.u16(4))
          layer.add(:seq, 'icmpv6.echo.sequence_number', cursor.u16(6))
        elsif [135, 136, 137].include?(type)
          family = { 135 => 'ns', 136 => 'na', 137 => 'rd' }.fetch(type)
          layer.add(:target, "icmpv6.nd.#{family}.target_address", cursor.bytes(8, 16), type: :ipv6)
          layer.add(:destination, 'icmpv6.rd.na.destination_address', cursor.bytes(24, 16), type: :ipv6) if type == 137
          if type == 136
            flags = cursor.u32(4)
            layer.add(:flags, 'icmpv6.nd.na.flag', flags, format: :hex)
            { r: 0x80000000, s: 0x40000000, o: 0x20000000 }.each do |name, mask|
              layer.add(name, "icmpv6.nd.na.flag.#{name}", (flags & mask).positive?)
            end
          end
        end
        if type == 134
          layer.add(:hop_limit, 'icmpv6.nd.ra.cur_hop_limit', cursor.u8(4))
          layer.add(:lifetime, 'icmpv6.nd.ra.router_lifetime', cursor.u16(6))
          flags = cursor.u8(5)
          layer.add(:flags, 'icmpv6.nd.ra.flag', flags, format: :hex)
          layer.add(:managed, 'icmpv6.nd.ra.flag.m', (flags & 0x80).positive?)
          layer.add(:other, 'icmpv6.nd.ra.flag.o', (flags & 0x40).positive?)
          layer.add(:reachable, 'icmpv6.nd.ra.reachable_time', cursor.u32(8))
          layer.add(:retrans, 'icmpv6.nd.ra.retrans_timer', cursor.u32(12))
        end
        if type.between?(133, 137)
          pos = length
          while pos < cursor.remaining
            opt = cursor.u8(pos)
            len = cursor.u8(pos + 1) * 8
            return layer.diagnose(:error, :bad_length, 'NDP option has zero length') if len.zero?
            cursor.check(pos, len)
            layer.add(:"option_type_#{pos}", 'icmpv6.opt.type', opt)
            layer.add(:"option_length_#{pos}", 'icmpv6.opt.length', len / 8)
            if [1, 2].include?(opt) && len >= 8
              layer.add(:"link_address_#{pos}", 'icmpv6.opt.linkaddr', cursor.bytes(pos + 2, 6), type: :mac)
            elsif opt == 3 && len == 32
              layer.add(:"prefix_length_#{pos}", 'icmpv6.opt.prefix.length', cursor.u8(pos + 2))
              flags = cursor.u8(pos + 3)
              layer.add(:"prefix_flags_#{pos}", 'icmpv6.opt.prefix.flag', flags, format: :hex)
              layer.add(:"prefix_onlink_#{pos}", 'icmpv6.opt.prefix.flag.l', (flags & 0x80).positive?)
              layer.add(:"prefix_autonomous_#{pos}", 'icmpv6.opt.prefix.flag.a', (flags & 0x40).positive?)
              layer.add(:"prefix_valid_#{pos}", 'icmpv6.opt.prefix.valid_lifetime', cursor.u32(pos + 4))
              layer.add(:"prefix_preferred_#{pos}", 'icmpv6.opt.prefix.preferred_lifetime', cursor.u32(pos + 8))
              layer.add(:"prefix_#{pos}", 'icmpv6.opt.prefix', cursor.bytes(pos + 16, 16), type: :ipv6)
            elsif opt == 4 && len >= 8
              layer.add(:"redirected_#{pos}", 'icmpv6.opt.redirected_packet', cursor.bytes(pos + 8, len - 8), type: :bytes)
            elsif opt == 5 && len == 8
              layer.add(:"mtu_#{pos}", 'icmpv6.opt.mtu', cursor.u32(pos + 4))
            else
              layer.add(:"option_#{pos}", 'icmpv6.opt.data', cursor.bytes(pos + 2, len - 2), type: :bytes)
            end
            pos += len
          end
          length = pos
        end
        layer.header_length, layer.payload_offset = length, layer.offset + length
        Checksum.verify(ctx, layer, cursor.bytes(0, cursor.remaining), 58)
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer)
        return nil unless layer[:type] < 128
        ctx.embedded = true
        Ipv6
      end
    end

    # @api private
    class Igmp < Dissector
      protocol :igmp, name: 'Internet Group Management Protocol', short: 'IGMP'
      dissects_on 'ip.proto', 2
      header do
        uint8 :type, 'igmp.type'
        uint8 :response, 'igmp.max_resp'
        uint16 :checksum, 'igmp.checksum'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        cursor, type = ctx.cursor, layer[:type]
        cursor.check(0, 8)
        version = type == 0x22 || (type == 0x11 && cursor.remaining >= 12) ? 3 : (type == 0x12 || (type == 0x11 && layer[:response].zero?) ? 1 : 2)
        layer.add(:version, 'igmp.version', version)
        pos = 8
        if type == 0x22
          count = cursor.u16(6)
          layer.add(:records, 'igmp.num_grp_recs', count)
          count.times do |record|
            cursor.check(pos, 8)
            sources, auxiliary = cursor.u16(pos + 2), cursor.u8(pos + 1) * 4
            cursor.check(pos, 8 + sources * 4 + auxiliary)
            layer.add(:"record_#{record}", 'igmp.record_type', cursor.u8(pos))
            layer.add(:"group_#{record}", 'igmp.maddr', cursor.u32(pos + 4), type: :ipv4)
            layer.add(:"sources_#{record}", 'igmp.num_src', sources)
            sources.times { |i| layer.add(:"source_#{record}_#{i}", 'igmp.saddr', cursor.u32(pos + 8 + i * 4), type: :ipv4) }
            layer.add(:"auxiliary_#{record}", 'igmp.aux_data', cursor.bytes(pos + 8 + sources * 4, auxiliary), type: :bytes) if auxiliary.positive?
            pos += 8 + sources * 4 + auxiliary
          end
        else
          layer.add(:group, 'igmp.maddr', cursor.u32(4), type: :ipv4)
          if version == 3
            sources = cursor.u16(10)
            cursor.check(8, 4 + sources * 4)
            layer.add(:suppress, 'igmp.s', (cursor.u8(8) & 8).positive?)
            layer.add(:robustness, 'igmp.qrv', cursor.u8(8) & 7)
            layer.add(:interval, 'igmp.qqic', cursor.u8(9))
            layer.add(:sources, 'igmp.num_src', sources)
            sources.times { |i| layer.add(:"source_#{i}", 'igmp.saddr', cursor.u32(12 + i * 4), type: :ipv4) }
            pos = 12 + sources * 4
          end
        end
        layer.header_length, layer.payload_offset = pos, layer.offset + pos
        Checksum.verify(ctx, layer, cursor.bytes(0, cursor.remaining))
      end
    end
  end
end
