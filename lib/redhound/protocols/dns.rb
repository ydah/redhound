# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Dns < StreamDissector
      # @api private
      class Malformed < StandardError; end
      TYPES = { 1 => 'A', 2 => 'NS', 5 => 'CNAME', 6 => 'SOA', 12 => 'PTR', 15 => 'MX',
                16 => 'TXT', 28 => 'AAAA', 33 => 'SRV', 41 => 'OPT', 64 => 'SVCB', 65 => 'HTTPS' }.freeze
      protocol :dns, name: 'Domain Name System', short: 'DNS'
      dissects_on 'udp.port', 53, 5353, 5355
      dissects_on 'tcp.port', 53, 5353, 5355

      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        cursor = ctx.cursor
        pos = 0
        transport = ctx.layers.last
        tcp = transport&.protocol == :tcp
        port = [transport&.[](:srcport), transport&.[](:dstport)].compact.sort.find { |value| [53, 5353, 5355].include?(value) }
        variant = { 5353 => :mdns, 5355 => :llmnr }.fetch(port, :dns)
        layer.values[:variant] = variant
        loop do
          if tcp
            len = cursor.u16(pos)
            put(layer, 'dns.length', len, :uint, pos, 2)
            raise Malformed, 'DNS message shorter than header' if len < 12
            pos += 2
            ending = pos + len
            layer.diagnose(:note, :truncated) if ending > cursor.remaining
            message(cursor.sub(cursor.start + pos, cursor.start + ending), layer, variant)
            pos = ending
          else
            message(cursor, layer, variant)
            pos = cursor.remaining
          end
          break unless tcp && pos < cursor.remaining
        end
      rescue Cursor::Truncated => e
        layer.diagnose(:note, :truncated, e.message)
      rescue Malformed => e
        layer.diagnose(:error, :malformed, e.message)
      ensure
        layer.header_length = cursor.remaining
        layer.payload_offset = layer.payload_end
      end

      # @rbs (Cursor cursor, Layer layer, Symbol variant) -> void
      def message(cursor, layer, variant)
        cursor.check(0, 12)
        base = cursor.start - layer.offset
        put(layer, 'dns.id', cursor.u16(0), :uint, base, 2)
        flags = cursor.u16(2)
        put(layer, 'dns.flags', flags, :uint, base + 2, 2)
        flag_bits = { response: [15, 1], opcode: [11, 15], authoritative: [10, 1], truncated: [9, 1],
                      recdesired: [8, 1], recavail: [7, 1], authenticated: [5, 1], checkdisable: [4, 1], rcode: [0, 15] }
        if variant == :llmnr
          %i[authoritative recdesired recavail authenticated checkdisable].each { |key| flag_bits.delete(key) }
          flag_bits.merge!(conflict: [10, 1], tentative: [8, 1])
        end
        flag_bits.each do |key, pair|
          next if key == :rcode && flags & 0x8000 == 0
          shift, mask = pair.fetch(0), pair.fetch(1)
          value = (flags >> shift) & mask
          put(layer, "dns.flags.#{key}", mask == 1 ? value == 1 : value, mask == 1 ? :boolean : :uint, base + 2, 2)
        end
        counts = cursor.unpack('n4', 8, 4)
        %w[queries answers auth_rr additional_rr].each_with_index do |name, i|
          put(layer, "dns.count.#{name}", counts[i], :uint, base + 4 + i * 2, 2)
        end
        pos = 12
        counts[0].times do
          name, after = read_name(cursor, pos)
          put(layer, 'dns.qry.name', name, :string, base + pos, after - pos)
          cursor.check(after, 4)
          put(layer, 'dns.qry.type', cursor.u16(after), :uint, base + after, 2)
          klass = cursor.u16(after + 2)
          put(layer, 'dns.qry.class', variant == :mdns ? klass & 0x7fff : klass, :uint, base + after + 2, 2)
          put(layer, 'dns.qry.qu', klass & 0x8000 != 0, :boolean, base + after + 2, 2) if variant == :mdns
          pos = after + 4
        end
        counts.drop(1).sum.times { pos = record(cursor, layer, pos, base, variant) }
      end

      # @rbs (Cursor cursor, Integer pos, ?Integer? limit, ?bool compression) -> [String, Integer]
      def read_name(cursor, pos, limit = nil, compression = true)
        limit ||= cursor.remaining
        labels, seen, wire_length, jumps, ending = [], {}, 1, 0, nil
        loop do
          raise Malformed, 'DNS name compression loop' if seen[pos]
          seen[pos] = true
          len = cursor.u8(pos)
          raise Malformed, 'DNS name exceeds record length' if ending.nil? && pos >= limit
          if len & 0xc0 == 0xc0
            raise Malformed, 'compressed target name is forbidden' unless compression
            raise Malformed, 'DNS pointer exceeds record length' if ending.nil? && pos + 2 > limit
            target = cursor.u16(pos) & 0x3fff
            raise Malformed, 'DNS pointer is not backward' unless target < pos
            jumps += 1
            raise Malformed, 'DNS compression exceeds 128 jumps' if jumps > 128
            ending ||= pos + 2
            pos = target
          else
            raise Malformed, 'invalid DNS label type' unless len & 0xc0 == 0
            pos += 1
            break if len.zero?
            wire_length += len + 1
            raise Malformed, 'DNS name exceeds 255 bytes' if wire_length > 255
            cursor.check(pos, len)
            raise Malformed, 'DNS label exceeds record length' if ending.nil? && pos + len > limit
            labels << cursor.bytes(pos, len)
            pos += len
          end
        end
        [labels.join('.'), ending || pos]
      end

      # @rbs (Cursor cursor, Layer layer, Integer pos, Integer base, Symbol variant) -> Integer
      def record(cursor, layer, pos, base, variant)
        name, after = read_name(cursor, pos)
        cursor.check(after, 10)
        type, klass, ttl, length = cursor.unpack('nnNn', 10, after)
        first, ending = after + 10, after + 10 + length
        cursor.check(first, length)
        if type == 33
          service, protocol, domain = name.split('.', 3)
          put(layer, 'dns.srv.service', service || '', :string, base + pos, after - pos)
          put(layer, 'dns.srv.proto', protocol || '', :string, base + pos, after - pos)
          put(layer, 'dns.srv.name', domain, :string, base + pos, after - pos) if domain
        else
          put(layer, 'dns.resp.name', name.empty? ? '<Root>' : name, :string, base + pos, after - pos)
        end
        put(layer, 'dns.resp.type', type, :uint, base + after, 2)
        put(layer, 'dns.resp.len', length, :uint, base + after + 8, 2)
        if type == 41
          put(layer, 'dns.rr.udp_payload_size', klass, :uint, base + after + 2, 2)
          put(layer, 'dns.resp.ext_rcode', ttl >> 24, :uint, base + after + 4, 1)
          put(layer, 'dns.resp.edns0_version', (ttl >> 16) & 255, :uint, base + after + 5, 1)
          put(layer, 'dns.resp.z', ttl & 0xffff, :uint, base + after + 6, 2)
          put(layer, 'dns.resp.z.do', ttl & 0x8000 != 0, :boolean, base + after + 6, 2)
          edns(cursor, layer, first, ending, base)
        else
          put(layer, 'dns.resp.class', variant == :mdns ? klass & 0x7fff : klass, :uint, base + after + 2, 2)
          put(layer, 'dns.resp.ttl', ttl, :uint, base + after + 4, 4)
          put(layer, 'dns.resp.cache_flush', klass & 0x8000 != 0, :boolean, base + after + 2, 2) if variant == :mdns
          rdata(cursor, layer, type, first, ending, base)
        end
        ending
      end

      # @rbs (Cursor cursor, Layer layer, Integer type, Integer pos, Integer ending, Integer base) -> void
      def rdata(cursor, layer, type, pos, ending, base)
        length = ending - pos
        case type
        when 1, 28
          expected = type == 1 ? 4 : 16
          return layer.diagnose(:error, :bad_length, 'invalid DNS address length') unless length == expected
          value = type == 1 ? cursor.u32(pos) : cursor.bytes(pos, 16)
          put(layer, type == 1 ? 'dns.a' : 'dns.aaaa', value, type == 1 ? :ipv4 : :ipv6, base + pos, length)
        when 2, 5, 12
          name, after = read_name(cursor, pos, ending)
          put(layer, { 2 => 'dns.ns', 5 => 'dns.cname', 12 => 'dns.ptr.domain_name' }.fetch(type), name, :string, base + pos, after - pos)
          raise Malformed, 'DNS name has trailing record bytes' unless after == ending
        when 15, 33
          width = type == 15 ? 2 : 6
          raise Malformed, 'DNS service record is too short' if length < width + 1
          names = type == 15 ? ['dns.mx.preference'] : %w[dns.srv.priority dns.srv.weight dns.srv.port]
          names.each_with_index { |name, i| put(layer, name, cursor.u16(pos + i * 2), :uint, base + pos + i * 2, 2) }
          name, after = read_name(cursor, pos + width, ending)
          put(layer, type == 15 ? 'dns.mx.mail_exchange' : 'dns.srv.target', name, :string, base + pos + width, after - pos - width)
          raise Malformed, 'DNS service record has trailing bytes' unless after == ending
        when 16
          while pos < ending
            len = cursor.u8(pos)
            raise Malformed, 'DNS TXT string exceeds record' if pos + 1 + len > ending
            put(layer, 'dns.txt', cursor.bytes(pos + 1, len), :string, base + pos + 1, len)
            pos += len + 1
          end
        when 6
          %w[mname rname].each do |key|
            name, after = read_name(cursor, pos, ending)
            put(layer, "dns.soa.#{key}", name, :string, base + pos, after - pos)
            pos = after
          end
          raise Malformed, 'invalid SOA integer section' unless ending - pos == 20
          %w[serial_number refresh_interval retry_interval expire_limit minimum_ttl].each_with_index do |key, i|
            put(layer, "dns.soa.#{key}", cursor.u32(pos + i * 4), :uint, base + pos + i * 4, 4)
          end
        when 64, 65 then service_binding(cursor, layer, pos, ending, base)
        else put(layer, 'dns.data', cursor.bytes(pos, length), :bytes, base + pos, length)
        end
      end

      # @rbs (Cursor cursor, Layer layer, Integer pos, Integer ending, Integer base) -> void
      def service_binding(cursor, layer, pos, ending, base)
        raise Malformed, 'short SVCB record' if ending - pos < 3
        priority = cursor.u16(pos)
        put(layer, 'dns.svcb.svcpriority', priority, :uint, base + pos, 2)
        name, after = read_name(cursor, pos + 2, ending, false)
        put(layer, 'dns.svcb.targetname', name, :string, base + pos + 2, after - pos - 2)
        pos, previous = after, -1
        while pos < ending
          raise Malformed, 'short SVCB parameter header' if ending - pos < 4
          key, len = cursor.u16(pos), cursor.u16(pos + 2)
          raise Malformed, 'invalid SVCB parameter order or length' if key <= previous || pos + 4 + len > ending
          previous = key
          put(layer, 'dns.svcb.svcparam.key', key, :uint, base + pos, 2)
          put(layer, 'dns.svcb.svcparam.value.length', len, :uint, base + pos + 2, 2)
          first = pos + 4
          case key
          when 0, 3, 4, 6
            size = { 0 => 2, 3 => 2, 4 => 4, 6 => 16 }.fetch(key)
            raise Malformed, 'invalid SVCB parameter size' if len.zero? || len % size != 0 || (key == 3 && len != 2)
            (len / size).times do |i|
              value = size == 16 ? cursor.bytes(first + i * size, size) : (size == 4 ? cursor.u32(first + i * size) : cursor.u16(first + i * size))
              name = { 0 => 'mandatory.key', 3 => 'port', 4 => 'ipv4hint.ip', 6 => 'ipv6hint.ip' }.fetch(key)
              put(layer, "dns.svcb.svcparam.#{name}", value, { 4 => :ipv4, 6 => :ipv6 }.fetch(key, :uint), base + first + i * size, size)
            end
          when 1
            while first < pos + 4 + len
              size = cursor.u8(first)
              raise Malformed, 'invalid SVCB ALPN size' if size.zero? || first + size + 1 > pos + 4 + len
              put(layer, 'dns.svcb.svcparam.alpn', cursor.bytes(first + 1, size), :string, base + first + 1, size)
              first += size + 1
            end
          when 2 then raise Malformed, 'no-default-alpn must be empty' unless len.zero?
          else put(layer, key == 7 ? 'dns.svcb.svcparam.dohpath' : 'dns.svcb.svcparam.value', cursor.bytes(first, len), key == 7 ? :string : :bytes, base + first, len)
          end
          pos += len + 4
        end
      end

      # @rbs (Cursor cursor, Layer layer, Integer pos, Integer ending, Integer base) -> void
      def edns(cursor, layer, pos, ending, base)
        while pos < ending
          raise Malformed, 'short EDNS option header' if ending - pos < 4
          code, len = cursor.u16(pos), cursor.u16(pos + 2)
          raise Malformed, 'EDNS option exceeds record' if pos + 4 + len > ending
          put(layer, 'dns.opt.code', code, :uint, base + pos, 2)
          put(layer, 'dns.opt.len', len, :uint, base + pos + 2, 2)
          put(layer, 'dns.opt.data', cursor.bytes(pos + 4, len), :bytes, base + pos + 4, len)
          if code == 10
            raise Malformed, 'invalid EDNS cookie length' unless len == 8 || len.between?(16, 40)
            put(layer, 'dns.opt.cookie.client', cursor.bytes(pos + 4, 8), :bytes, base + pos + 4, 8)
            put(layer, 'dns.opt.cookie.server', cursor.bytes(pos + 12, len - 8), :bytes, base + pos + 12, len - 8) if len > 8
          end
          pos += len + 4
        end
      end

      # @rbs (Layer layer, String name, untyped value, Symbol type, Integer offset, Integer length) -> void
      def put(layer, name, value, type, offset, length)
        layer.add("#{name}_#{layer.definitions.length}".to_sym, name, value, type: type, offset: offset, length: length)
      end

      # @rbs (Layer layer) -> String
      def summary(layer)
        name = layer.fields.find { |field| field.name == 'dns.qry.name' }&.display || ''
        type = TYPES[layer.field_value('dns.qry.type')] || layer.field_value('dns.qry.type')
        label = { mdns: 'mDNS', llmnr: 'LLMNR' }.fetch(layer[:variant], 'DNS')
        "#{label} #{layer.field_value('dns.flags.response') ? 'response' : 'query'} #{type} #{name}"
      end
    end
  end
end
