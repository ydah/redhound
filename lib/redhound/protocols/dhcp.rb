# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Dhcp < Dissector
      MESSAGE_TYPES = { 1 => 'Discover', 2 => 'Offer', 3 => 'Request', 4 => 'Decline', 5 => 'ACK',
                        6 => 'NAK', 7 => 'Release', 8 => 'Inform' }.freeze
      ADDRESS_OPTIONS = { 1 => 'subnet_mask', 3 => 'router', 6 => 'domain_name_server',
                          50 => 'requested_ip_address', 54 => 'dhcp_server_id' }.freeze
      protocol :dhcp, name: 'Dynamic Host Configuration Protocol', short: 'DHCP'
      dissects_on 'udp.port', 67, 68
      header do
        uint8 :type, 'dhcp.type'
        uint8 :hw_type, 'dhcp.hw.type'
        uint8 :hw_len, 'dhcp.hw.len'
        uint8 :hops, 'dhcp.hops'
        uint32 :xid, 'dhcp.id', format: :hex
        uint16 :secs, 'dhcp.secs'
        uint16 :flags, 'dhcp.flags', format: :hex
        ipv4 :client, 'dhcp.ip.client'
        ipv4 :your, 'dhcp.ip.your'
        ipv4 :server, 'dhcp.ip.server'
        ipv4 :relay, 'dhcp.ip.relay'
      end

      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        cursor = ctx.cursor
        cursor.check(0, 236)
        return layer.diagnose(:error, :bad_length, 'hardware address is longer than 16 bytes') if layer[:hw_len] > 16
        put(layer, 'dhcp.hw.mac_addr', cursor.bytes(28, layer[:hw_len]),
            layer[:hw_type] == 1 && layer[:hw_len] == 6 ? :mac : :bytes, 28, layer[:hw_len])
        put(layer, 'dhcp.server', cursor.bytes(44, 64).split("\0", 2).first || '', :string, 44, 64)
        put(layer, 'dhcp.file', cursor.bytes(108, 128).split("\0", 2).first || '', :string, 108, 128)
        return if cursor.remaining == 236
        cursor.check(236, 4)
        unless cursor.u32(236) == 0x63825363
          put(layer, 'dhcp.vendor', cursor.bytes(236, cursor.remaining - 236), :bytes, 236, cursor.remaining - 236)
          return
        end
        put(layer, 'dhcp.cookie', 0x63825363, :uint, 236, 4)
        # @type var options: Hash[Integer, untyped]
        options = Hash.new
        read_options(cursor, layer, 240, cursor.remaining, options)
        overload = options[52]&.map { |entry| entry[0] }&.join
        if overload
          return layer.diagnose(:error, :bad_length, 'invalid DHCP overload option') unless overload.bytesize == 1 && overload.getbyte(0).between?(1, 3)
          read_options(cursor, layer, 108, 236, options) if overload.getbyte(0) & 1 != 0
          read_options(cursor, layer, 44, 108, options) if overload.getbyte(0) & 2 != 0
        end
        options.each do |code, entries|
          value = entries.map { |entry| entry[0] }.join
          decode_option(layer, code, value, entries.first[1])
        end
      rescue Cursor::Truncated => e
        layer.diagnose(:note, :truncated, e.message)
      ensure
        layer.header_length = cursor.remaining
        layer.payload_offset = layer.payload_end
      end

      # @rbs (Cursor cursor, Layer layer, Integer pos, Integer ending, untyped options) -> void
      def read_options(cursor, layer, pos, ending, options)
        while pos < ending
          code = cursor.u8(pos)
          pos += 1
          next if code.zero?
          break if code == 255
          raise Cursor::Truncated, 'truncated DHCP option length' if pos >= ending
          len = cursor.u8(pos)
          pos += 1
          raise Cursor::Truncated, 'DHCP option exceeds available bytes' if pos + len > ending
          value = cursor.bytes(pos, len)
          put(layer, 'dhcp.option.type', code, :uint, pos - 2, 1)
          put(layer, 'dhcp.option.length', len, :uint, pos - 1, 1)
          put(layer, 'dhcp.option.value', value, :bytes, pos, len)
          options[code] = Array.new unless options.key?(code)
          options[code] << [value, pos]
          pos += len
        end
      end

      # @rbs (Layer layer, Integer code, String value, Integer offset) -> void
      def decode_option(layer, code, value, offset)
        length = value.bytesize
        if ADDRESS_OPTIONS.key?(code)
          valid = length.positive? && length % 4 == 0 && (![1, 50, 54].include?(code) || length == 4)
          return layer.diagnose(:error, :bad_length, "invalid DHCP option #{code} length") unless valid
          (length / 4).times do |i|
            put(layer, "dhcp.option.#{ADDRESS_OPTIONS[code]}", value.unpack1('N', offset: i * 4), :ipv4, offset + i * 4, 4)
          end
        else
          case code
          when 53, 52
            return layer.diagnose(:error, :bad_length, "invalid DHCP option #{code} length") unless length == 1
            put(layer, code == 53 ? 'dhcp.option.dhcp' : 'dhcp.option.overload', value.getbyte(0), :uint, offset, 1)
          when 51
            return layer.diagnose(:error, :bad_length, 'invalid DHCP lease length') unless length == 4
            put(layer, 'dhcp.option.ip_address_lease_time', value.unpack1('N'), :uint, offset, 4)
          when 55
            length.times { |i| put(layer, 'dhcp.option.request_list_item', value.getbyte(i), :uint, offset + i, 1) }
          when 61
            return layer.diagnose(:error, :bad_length, 'DHCP client ID must include type and identifier') if length < 2
            put(layer, 'dhcp.option.client_id', value, :bytes, offset, length)
            put(layer, 'dhcp.option.client_id.type', value.getbyte(0), :uint, offset, 1)
            put(layer, 'dhcp.option.client_id.hw_mac_addr', value.byteslice(1, 6), :mac, offset + 1, 6) if length == 7 && value.getbyte(0) == 1
          when 12 then put(layer, 'dhcp.option.hostname', value, :string, offset, length)
          end
        end
      end

      # @rbs (Layer layer, String name, untyped value, Symbol type, Integer offset, Integer length) -> void
      def put(layer, name, value, type, offset, length)
        layer.add("#{name}_#{layer.definitions.length}".to_sym, name, value, type: type, offset: offset, length: length)
      end

      # @rbs (Layer layer) -> String
      def summary(layer) = "DHCP #{MESSAGE_TYPES[layer.field_value('dhcp.option.dhcp')] || 'BOOTP'}, xid #{format('0x%x', layer[:xid] || 0)}"
    end
  end
end
