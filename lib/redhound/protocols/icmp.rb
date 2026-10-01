# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Icmp < Dissector
      TYPES = { 0 => 'Echo Reply', 3 => 'Destination Unreachable', 4 => 'Source Quench', 5 => 'Redirect',
                8 => 'Echo Request', 9 => 'Router Advertisement', 10 => 'Router Solicitation', 11 => 'Time Exceeded',
                12 => 'Parameter Problem', 13 => 'Timestamp', 14 => 'Timestamp Reply', 17 => 'Address Mask Request', 18 => 'Address Mask Reply' }.freeze
      CODES = {
        3 => { 0 => 'Network Unreachable', 1 => 'Host Unreachable', 2 => 'Protocol Unreachable', 3 => 'Port Unreachable',
               4 => 'Fragmentation Needed', 5 => 'Source Route Failed', 6 => 'Network Unknown', 7 => 'Host Unknown',
               8 => 'Source Host Isolated', 9 => 'Network Administratively Prohibited', 10 => 'Host Administratively Prohibited',
               11 => 'Network Unreachable for TOS', 12 => 'Host Unreachable for TOS', 13 => 'Administratively Prohibited',
               14 => 'Host Precedence Violation', 15 => 'Precedence Cutoff' },
        5 => { 0 => 'Redirect Network', 1 => 'Redirect Host', 2 => 'Redirect TOS Network', 3 => 'Redirect TOS Host' },
        11 => { 0 => 'TTL Expired', 1 => 'Reassembly Timeout' },
        12 => { 0 => 'Invalid Pointer', 1 => 'Missing Option', 2 => 'Invalid Length' }
      }.freeze
      protocol :icmp, name: 'Internet Control Message Protocol', short: 'ICMP'
      dissects_on 'ip.proto', 1
      header do
        uint8 :type, 'icmp.type', enum: TYPES
        uint8 :code, 'icmp.code'
        uint16 :checksum, 'icmp.checksum', format: :hex
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        layer.definitions[1] = layer.definitions[1].with(enum: CODES[layer[:type]])
        if [0, 8, 13, 14, 17, 18].include?(layer[:type])
          layer.add(:ident, 'icmp.ident', ctx.cursor.u16(4), offset: 4, length: 2)
          layer.add(:seq, 'icmp.seq', ctx.cursor.u16(6), offset: 6, length: 2)
        else
          ctx.cursor.check(0, 8)
          if layer[:type] == 3 && layer[:code] == 4
            layer.add(:mtu, 'icmp.mtu', ctx.cursor.u16(6), offset: 6, length: 2)
          end
        end
        layer.header_length, layer.payload_offset = 8, layer.offset + 8
        Checksum.verify(ctx, layer, ctx.cursor.bytes(0, ctx.cursor.remaining))
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer)
        return nil unless [3, 4, 5, 11, 12].include?(layer[:type])
        ctx.embedded = true
        Ipv4
      end
      # @rbs (Layer layer) -> String
      def summary(layer)
        text = "ICMP type #{layer[:type]}, code #{layer[:code]}"
        text += ", id #{layer[:ident]}, seq #{layer[:seq]}" if layer[:ident]
        text += ", mtu #{layer[:mtu]}" if layer[:mtu]
        text
      end
    end

    # @api private
    class Icmpv6 < Dissector
      TYPES = { 1 => 'Destination Unreachable', 2 => 'Packet Too Big', 3 => 'Time Exceeded', 4 => 'Parameter Problem',
                128 => 'Echo Request', 129 => 'Echo Reply', 133 => 'Router Solicitation', 134 => 'Router Advertisement',
                135 => 'Neighbor Solicitation', 136 => 'Neighbor Advertisement', 137 => 'Redirect' }.freeze
      CODES = {
        1 => { 0 => 'No Route', 1 => 'Administratively Prohibited', 2 => 'Beyond Source Scope', 3 => 'Address Unreachable',
               4 => 'Port Unreachable', 5 => 'Source Policy Failure', 6 => 'Reject Route', 7 => 'Source Routing Error' },
        3 => { 0 => 'Hop Limit Exceeded', 1 => 'Reassembly Timeout' },
        4 => { 0 => 'Invalid Header Field', 1 => 'Unknown Next Header', 2 => 'Unknown Option' }
      }.freeze
      protocol :icmpv6, name: 'ICMPv6 / Neighbor Discovery', short: 'ICMP6'
      dissects_on 'ip.proto', 58
      header do
        uint8 :type, 'icmpv6.type', enum: TYPES
        uint8 :code, 'icmpv6.code'
        uint16 :checksum, 'icmpv6.checksum'
      end
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        cursor, type = ctx.cursor, layer[:type]
        layer.definitions[1] = layer.definitions[1].with(enum: CODES[type])
        length = case type
                 when 133 then 8
                 when 134 then 16
                 when 135, 136 then 24
                 when 137 then 40
                 else 8
                 end
        cursor.check(0, length)
        if [128, 129].include?(type)
          layer.add(:ident, 'icmpv6.echo.identifier', cursor.u16(4), offset: 4, length: 2)
          layer.add(:seq, 'icmpv6.echo.sequence_number', cursor.u16(6), offset: 6, length: 2)
        elsif [135, 136, 137].include?(type)
          family = { 135 => 'ns', 136 => 'na', 137 => 'rd' }.fetch(type)
          layer.add(:target, "icmpv6.nd.#{family}.target_address", cursor.bytes(8, 16), type: :ipv6, offset: 8, length: 16)
          layer.add(:destination, 'icmpv6.rd.na.destination_address', cursor.bytes(24, 16), type: :ipv6, offset: 24, length: 16) if type == 137
          if type == 136
            flags = cursor.u32(4)
            layer.add(:flags, 'icmpv6.nd.na.flag', flags, format: :hex, offset: 4, length: 4)
            { r: 0x80000000, s: 0x40000000, o: 0x20000000 }.each do |name, mask|
              layer.add(name, "icmpv6.nd.na.flag.#{name}", (flags & mask).positive?, type: :boolean, offset: 4, length: 4)
            end
          end
        end
        if type == 134
          layer.add(:hop_limit, 'icmpv6.nd.ra.cur_hop_limit', cursor.u8(4), offset: 4, length: 1)
          layer.add(:lifetime, 'icmpv6.nd.ra.router_lifetime', cursor.u16(6), offset: 6, length: 2)
          flags = cursor.u8(5)
          layer.add(:flags, 'icmpv6.nd.ra.flag', flags, format: :hex, offset: 5, length: 1)
          layer.add(:managed, 'icmpv6.nd.ra.flag.m', (flags & 0x80).positive?, type: :boolean, offset: 5, length: 1)
          layer.add(:other, 'icmpv6.nd.ra.flag.o', (flags & 0x40).positive?, type: :boolean, offset: 5, length: 1)
          layer.add(:reachable, 'icmpv6.nd.ra.reachable_time', cursor.u32(8), offset: 8, length: 4)
          layer.add(:retrans, 'icmpv6.nd.ra.retrans_timer', cursor.u32(12), offset: 12, length: 4)
        end
        if type.between?(133, 137)
          pos = length
          while pos < cursor.remaining
            opt = cursor.u8(pos)
            len = cursor.u8(pos + 1) * 8
            return layer.diagnose(:error, :bad_length, 'NDP option has zero length') if len.zero?
            cursor.check(pos, len)
            layer.add(:"option_type_#{pos}", 'icmpv6.opt.type', opt, offset: pos, length: 1)
            layer.add(:"option_length_#{pos}", 'icmpv6.opt.length', len / 8, offset: pos + 1, length: 1)
            if [1, 2].include?(opt) && len >= 8
              layer.add(:"link_address_#{pos}", 'icmpv6.opt.linkaddr', cursor.bytes(pos + 2, 6), type: :mac, offset: pos + 2, length: 6)
            elsif opt == 3 && len == 32
              layer.add(:"prefix_length_#{pos}", 'icmpv6.opt.prefix.length', cursor.u8(pos + 2), offset: pos + 2, length: 1)
              flags = cursor.u8(pos + 3)
              layer.add(:"prefix_flags_#{pos}", 'icmpv6.opt.prefix.flag', flags, format: :hex, offset: pos + 3, length: 1)
              layer.add(:"prefix_onlink_#{pos}", 'icmpv6.opt.prefix.flag.l', (flags & 0x80).positive?, type: :boolean, offset: pos + 3, length: 1)
              layer.add(:"prefix_autonomous_#{pos}", 'icmpv6.opt.prefix.flag.a', (flags & 0x40).positive?, type: :boolean, offset: pos + 3, length: 1)
              layer.add(:"prefix_valid_#{pos}", 'icmpv6.opt.prefix.valid_lifetime', cursor.u32(pos + 4), offset: pos + 4, length: 4)
              layer.add(:"prefix_preferred_#{pos}", 'icmpv6.opt.prefix.preferred_lifetime', cursor.u32(pos + 8), offset: pos + 8, length: 4)
              layer.add(:"prefix_#{pos}", 'icmpv6.opt.prefix', cursor.bytes(pos + 16, 16), type: :ipv6, offset: pos + 16, length: 16)
            elsif opt == 4 && len >= 8
              layer.add(:"redirected_#{pos}", 'icmpv6.opt.redirected_packet', cursor.bytes(pos + 8, len - 8), type: :bytes, offset: pos + 8, length: len - 8)
            elsif opt == 5 && len == 8
              layer.add(:"mtu_#{pos}", 'icmpv6.opt.mtu', cursor.u32(pos + 4), offset: pos + 4, length: 4)
            else
              layer.add(:"option_#{pos}", 'icmpv6.opt.data', cursor.bytes(pos + 2, len - 2), type: :bytes, offset: pos + 2, length: len - 2)
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
        layer.definitions.reject! { |field| field.key == :response } if [0x12, 0x22].include?(type)
        cursor.check(0, 8)
        version = type == 0x22 || (type == 0x11 && cursor.remaining >= 12) ? 3 : (type == 0x12 || (type == 0x11 && layer[:response].zero?) ? 1 : 2)
        layer.add(:version, 'igmp.version', version)
        pos = 8
        if type == 0x22
          count = cursor.u16(6)
          layer.add(:records, 'igmp.num_grp_recs', count, offset: 6, length: 2)
          count.times do |record|
            cursor.check(pos, 8)
            sources, auxiliary = cursor.u16(pos + 2), cursor.u8(pos + 1) * 4
            cursor.check(pos, 8 + sources * 4 + auxiliary)
            layer.add(:"record_#{record}", 'igmp.record_type', cursor.u8(pos), offset: pos, length: 1)
            layer.add(:"group_#{record}", 'igmp.maddr', cursor.u32(pos + 4), type: :ipv4, offset: pos + 4, length: 4)
            layer.add(:"sources_#{record}", 'igmp.num_src', sources, offset: pos + 2, length: 2)
            sources.times { |i| layer.add(:"source_#{record}_#{i}", 'igmp.saddr', cursor.u32(pos + 8 + i * 4), type: :ipv4, offset: pos + 8 + i * 4, length: 4) }
            layer.add(:"auxiliary_#{record}", 'igmp.aux_data', cursor.bytes(pos + 8 + sources * 4, auxiliary), type: :bytes, offset: pos + 8 + sources * 4, length: auxiliary) if auxiliary.positive?
            pos += 8 + sources * 4 + auxiliary
          end
        else
          layer.add(:group, 'igmp.maddr', cursor.u32(4), type: :ipv4, offset: 4, length: 4)
          if version == 3
            sources = cursor.u16(10)
            cursor.check(8, 4 + sources * 4)
            layer.add(:suppress, 'igmp.s', (cursor.u8(8) & 8).positive?, type: :boolean, offset: 8, length: 1)
            layer.add(:robustness, 'igmp.qrv', cursor.u8(8) & 7, offset: 8, length: 1)
            layer.add(:interval, 'igmp.qqic', cursor.u8(9), offset: 9, length: 1)
            layer.add(:sources, 'igmp.num_src', sources, offset: 10, length: 2)
            sources.times { |i| layer.add(:"source_#{i}", 'igmp.saddr', cursor.u32(12 + i * 4), type: :ipv4, offset: 12 + i * 4, length: 4) }
            pos = 12 + sources * 4
          end
        end
        layer.header_length, layer.payload_offset = pos, layer.offset + pos
        Checksum.verify(ctx, layer, cursor.bytes(0, cursor.remaining))
      end
    end
  end
end
