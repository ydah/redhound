# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Tls < StreamDissector
      # @type ivar @ranges: Array[untyped]
      # @api private
      class BadLength < StandardError; end
      CONTENT_TYPES = { 20 => 'Change Cipher Spec', 21 => 'Alert', 22 => 'Handshake', 23 => 'Application Data', 24 => 'Heartbeat' }.freeze
      HANDSHAKES = { 1 => 'Client Hello', 2 => 'Server Hello', 4 => 'New Session Ticket', 8 => 'Encrypted Extensions',
                     11 => 'Certificate', 12 => 'Server Key Exchange', 14 => 'Server Hello Done', 15 => 'Certificate Verify',
                     16 => 'Client Key Exchange', 20 => 'Finished', 24 => 'Key Update' }.freeze
      protocol :tls, name: 'Transport Layer Security', short: 'TLS'
      dissects_on 'tcp.port', 443

      # @rbs (Context ctx, Cursor cursor) -> bool
      def self.heuristic?(ctx, cursor)
        cursor.remaining >= 5 && CONTENT_TYPES.key?(cursor.u8(0)) && cursor.u16(1).between?(0x0300, 0x0303) && cursor.u16(3) <= 18_432
      end

      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        cursor = ctx.cursor
        pos, encrypted = 0, ctx.packet.meta[:tls_encrypted] == true
        handshake_data = ''.b
        @ranges = Array.new
        while pos < cursor.remaining
          if pos + 5 > cursor.remaining
            layer.diagnose(:note, :truncated, 'incomplete TLS record header')
            break
          end
          type, version, length = cursor.unpack('Cnn', 5, pos)
          put(layer, 'tls.record.content_type', type, :uint, pos, 1)
          put(layer, 'tls.record.version', version, :uint, pos + 1, 2)
          put(layer, 'tls.record.length', length, :uint, pos + 3, 2)
          raise BadLength, 'invalid TLS record version, content type or length' unless CONTENT_TYPES.key?(type) && version.between?(0x0300, 0x0303) && length <= 18_432
          available = [length, cursor.remaining - pos - 5].min
          body = cursor.bytes(pos + 5, available)
          if available < length && type != 22
            layer.diagnose(:note, :truncated, 'incomplete TLS record')
            break
          end
          if type == 22 && !encrypted
            @ranges << [handshake_data.bytesize, pos + 5, available] if available.positive?
            handshake_data << body
          elsif type == 20
            raise BadLength, 'invalid ChangeCipherSpec' unless body == "\1"
            encrypted = true
          elsif type == 21 && !encrypted
            raise BadLength, 'invalid TLS alert length' unless length == 2
            put(layer, 'tls.alert_message.level', cursor.u8(pos + 5), :uint, pos + 5, 1)
            put(layer, 'tls.alert_message.desc', cursor.u8(pos + 6), :uint, pos + 6, 1)
          else
            put(layer, 'tls.app_data', body, :bytes, pos + 5, available)
          end
          if available < length
            layer.diagnose(:note, :truncated, 'incomplete TLS record')
            break
          end
          pos += length + 5
        end
        handshakes(layer, Cursor.new(handshake_data)) unless handshake_data.empty?
      rescue Cursor::Truncated => e
        layer.diagnose(:note, :truncated, e.message)
      rescue BadLength => e
        layer.diagnose(:error, :bad_length, e.message)
      ensure
        layer.header_length = cursor.remaining
        layer.payload_offset = layer.payload_end
      end

      # @rbs (Layer layer, Cursor cursor) -> void
      def handshakes(layer, cursor)
        pos = 0
        while pos < cursor.remaining
          cursor.check(pos, 4)
          type = cursor.u8(pos)
          length = (cursor.u8(pos + 1) << 16) | cursor.u16(pos + 2)
          put(layer, 'tls.handshake.type', type, :uint, pos, 1, true)
          put(layer, 'tls.handshake.length', length, :uint, pos + 1, 3, true)
          cursor.check(pos + 4, length)
          body = cursor.sub(cursor.start + pos + 4, cursor.start + pos + 4 + length)
          hello(layer, body, type) if [1, 2].include?(type)
          extensions(layer, body, 0, false) if type == 8
          pos += length + 4
        end
      end

      # @rbs (Layer layer, Cursor cursor, Integer type) -> void
      def hello(layer, cursor, type)
        cursor.check(0, 35)
        base = cursor.start
        put(layer, 'tls.handshake.version', cursor.u16(0), :uint, base, 2, true)
        put(layer, 'tls.handshake.random', cursor.bytes(2, 32), :bytes, base + 2, 32, true)
        session_length = cursor.u8(34)
        raise BadLength, 'TLS session ID exceeds 32 bytes' if session_length > 32
        cursor.check(35, session_length)
        put(layer, 'tls.handshake.session_id', cursor.bytes(35, session_length), :bytes, base + 35, session_length, true)
        pos = 35 + session_length
        client = type == 1
        if client
          cipher_length = cursor.u16(pos)
          raise BadLength, 'invalid TLS cipher suite vector' if cipher_length.zero? || cipher_length.odd?
          pos += 2
          cursor.check(pos, cipher_length)
          (cipher_length / 2).times { |i| put(layer, 'tls.handshake.ciphersuite', cursor.u16(pos + i * 2), :uint, base + pos + i * 2, 2, true) }
          pos += cipher_length
          compression_length = cursor.u8(pos)
          raise BadLength, 'empty TLS compression vector' if compression_length.zero?
          cursor.check(pos + 1, compression_length)
          put(layer, 'tls.handshake.comp_methods', cursor.bytes(pos + 1, compression_length), :bytes, base + pos + 1, compression_length, true)
          pos += 1 + compression_length
        else
          put(layer, 'tls.handshake.ciphersuite', cursor.u16(pos), :uint, base + pos, 2, true)
          put(layer, 'tls.handshake.comp_method', cursor.u8(pos + 2), :uint, base + pos + 2, 1, true)
          pos += 3
        end
        extensions(layer, cursor, pos, client) if pos < cursor.remaining
      rescue Cursor::Truncated => e
        raise BadLength, e.message
      end

      # @rbs (Layer layer, Cursor cursor, Integer pos, bool client) -> void
      def extensions(layer, cursor, pos, client)
        length = cursor.u16(pos)
        raise BadLength, 'TLS extensions length disagrees with handshake' unless pos + 2 + length == cursor.remaining
        ending = pos + 2 + length
        put(layer, 'tls.handshake.extensions_length', length, :uint, cursor.start + pos, 2, true)
        pos += 2
        # @type var seen: Hash[Integer, bool]
        seen = {}
        while pos < ending
          raise BadLength, 'short TLS extension header' if pos + 4 > ending
          type, size = cursor.u16(pos), cursor.u16(pos + 2)
          raise BadLength, 'duplicate or oversized TLS extension' if seen[type] || pos + 4 + size > ending
          seen[type] = true
          put(layer, 'tls.handshake.extension.type', type, :uint, cursor.start + pos, 2, true)
          put(layer, 'tls.handshake.extension.len', size, :uint, cursor.start + pos + 2, 2, true)
          extension = cursor.sub(cursor.start + pos + 4, cursor.start + pos + 4 + size)
          case type
          when 0 then server_names(layer, extension) unless size.zero? && !client
          when 16 then alpn(layer, extension)
          when 43 then versions(layer, extension, client)
          else put(layer, 'tls.handshake.extension.data', extension.bytes(0, size), :bytes, extension.start, size, true)
          end
          pos += size + 4
        end
      rescue Cursor::Truncated => e
        raise BadLength, e.message
      end

      # @rbs (Layer layer, Cursor cursor) -> void
      def server_names(layer, cursor)
        length = cursor.u16(0)
        raise BadLength, 'invalid TLS server name list length' unless length.positive? && length + 2 == cursor.remaining
        pos, seen = 2, {}
        while pos < cursor.remaining
          raise BadLength, 'short TLS server name entry' if pos + 3 > cursor.remaining
          type, length = cursor.u8(pos), cursor.u16(pos + 1)
          raise BadLength, 'duplicate or invalid TLS server name entry' if seen[type] || length.zero? || pos + 3 + length > cursor.remaining
          seen[type] = true
          put(layer, 'tls.handshake.extensions_server_name_type', type, :uint, cursor.start + pos, 1, true)
          put(layer, 'tls.handshake.extensions_server_name', cursor.bytes(pos + 3, length), :string, cursor.start + pos + 3, length, true) if type.zero?
          pos += length + 3
        end
      end

      # @rbs (Layer layer, Cursor cursor) -> void
      def alpn(layer, cursor)
        length = cursor.u16(0)
        raise BadLength, 'invalid TLS ALPN list length' unless length >= 2 && length + 2 == cursor.remaining
        pos = 2
        while pos < cursor.remaining
          length = cursor.u8(pos)
          raise BadLength, 'invalid TLS ALPN protocol length' if length.zero? || pos + 1 + length > cursor.remaining
          put(layer, 'tls.handshake.extensions_alpn_str', cursor.bytes(pos + 1, length), :string, cursor.start + pos + 1, length, true)
          pos += length + 1
        end
      end

      # @rbs (Layer layer, Cursor cursor, bool client) -> void
      def versions(layer, cursor, client)
        pos = client ? 1 : 0
        length = client ? cursor.u8(0) : 2
        raise BadLength, 'invalid TLS supported version vector' unless length.positive? && length.even? && pos + length == cursor.remaining
        (length / 2).times do |i|
          put(layer, 'tls.handshake.extensions.supported_version', cursor.u16(pos + i * 2), :uint, cursor.start + pos + i * 2, 2, true)
        end
      end

      # @rbs (Integer logical) -> Integer
      def wire_offset(logical)
        range = @ranges.bsearch { |entry| entry[0] + entry[2] > logical } || @ranges.last
        range ? range[1] + logical - range[0] : logical
      end

      # @rbs (Layer layer, String name, untyped value, Symbol type, Integer offset, Integer length, ?bool handshake) -> void
      def put(layer, name, value, type, offset, length, handshake = false)
        if handshake
          ending = length.positive? ? wire_offset(offset + length - 1) + 1 : wire_offset(offset)
          offset = wire_offset(offset)
          length = ending - offset
        end
        layer.add("#{name}_#{layer.definitions.length}".to_sym, name, value, type: type, offset: offset, length: length)
      end

      # @rbs (Layer layer) -> String
      def summary(layer)
        name = layer.fields.find { |field| field.name == 'tls.handshake.extensions_server_name' }&.display
        label = HANDSHAKES[layer.field_value('tls.handshake.type')] || CONTENT_TYPES[layer.field_value('tls.record.content_type')]
        "TLS #{label}#{name ? " #{name}" : ''}"
      end
    end
  end
end
