# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Http < StreamDissector
      HEADER_LIMIT = 65_536
      TOKEN = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/n
      HEADERS = %w[host user_agent accept content_type content_length transfer_encoding connection
                   server location referer cookie set_cookie authorization cache_control].freeze
      protocol :http, name: 'Hypertext Transfer Protocol', short: 'HTTP'
      dissects_on 'tcp.port', 80, 8080, 8000

      # @rbs (Context ctx, Cursor cursor) -> bool
      def self.heuristic?(ctx, cursor)
        sample = cursor.bytes(0, [cursor.remaining, 128].min)
        sample.match?(/\A(?:HTTP\/1\.[01] |[A-Z]{3,20} \S+ HTTP\/1\.[01](?:\r\n|\z))/n)
      end

      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        bytes = ctx.cursor.bytes(0, ctx.cursor.remaining)
        pos = 0
        while pos < bytes.bytesize
          first = bytes.index("\r\n", pos)
          return layer.diagnose(:note, :truncated, 'incomplete HTTP start line') unless first
          return layer.diagnose(:error, :malformed, 'HTTP start line is too long') if first - pos > HEADER_LIMIT
          line = bytes.byteslice(pos, first - pos)
          response = line.start_with?('HTTP/')
          status = start_line(layer, line, pos, response)
          return if layer.error?
          ending = bytes.index("\r\n\r\n", pos)
          return layer.diagnose(:note, :truncated, 'incomplete HTTP headers') unless ending
          return layer.diagnose(:error, :malformed, 'HTTP headers exceed 64 KiB') if ending - pos > HEADER_LIMIT
          headers = parse_headers(layer, bytes, first + 2, ending + 2)
          return if layer.error?
          body_start = ending + 4
          length_values = headers.fetch('content-length', []).flat_map { |value| value.empty? ? [''] : value.split(',', -1).map(&:strip) }
          unless length_values.all? { |value| value.match?(/\A[0-9]+\z/n) } && length_values.uniq.length <= 1
            return layer.diagnose(:error, :malformed, 'conflicting or invalid Content-Length')
          end
          content_length = length_values.first&.to_i
          transfer = headers.fetch('transfer-encoding', []).join(',').downcase.split(',').map(&:strip)
          if !transfer.empty? && content_length
            return layer.diagnose(:error, :malformed, 'Transfer-Encoding and Content-Length conflict')
          end
          no_body = response && (ctx.packet.meta[:http_head_response] == true || status.between?(100, 199) || [204, 304].include?(status))
          if no_body
            pos = body_start
          elsif transfer.last == 'chunked'
            body, pos = chunked(layer, bytes, body_start)
            put(layer, 'http.file_data', body, :bytes, body_start, pos - body_start) unless body.empty?
          elsif !transfer.empty?
            return layer.diagnose(:error, :malformed, 'request transfer coding must end in chunked') unless response
            put(layer, 'http.file_data', bytes.byteslice(body_start..), :bytes, body_start, bytes.bytesize - body_start)
            pos = bytes.bytesize
          elsif content_length
            available = [content_length, bytes.bytesize - body_start].min
            put(layer, 'http.file_data', bytes.byteslice(body_start, available), :bytes, body_start, available) if available.positive?
            pos = body_start + available
            layer.diagnose(:note, :truncated, 'incomplete HTTP body') if available < content_length
          elsif response
            put(layer, 'http.file_data', bytes.byteslice(body_start..), :bytes, body_start, bytes.bytesize - body_start) if body_start < bytes.bytesize
            pos = bytes.bytesize
          else
            pos = body_start
          end
          break if layer.error?
        end
      ensure
        layer.header_length = ctx.cursor.remaining
        layer.payload_offset = layer.payload_end
      end

      # @rbs (Layer layer, String line, Integer offset, bool response) -> Integer
      def start_line(layer, line, offset, response)
        if response
          match = /\A(HTTP\/1\.[01]) ([0-9]{3})(?: (.*))?\z/n.match(line)
          return layer.diagnose(:error, :malformed, 'invalid HTTP status line') && 0 unless match
          put(layer, 'http.response.version', match[1], :string, offset, match[1].bytesize)
          put(layer, 'http.response.code', match[2].to_i, :uint, offset + match[1].bytesize + 1, 3)
          put(layer, 'http.response.phrase', match[3] || '', :string, offset + match[1].bytesize + 5, (match[3] || '').bytesize)
          match[2].to_i
        else
          match = /\A([^ ]+) ([^ ]+) (HTTP\/1\.[01])\z/n.match(line)
          return layer.diagnose(:error, :malformed, 'invalid HTTP request line') && 0 unless match && match[1].match?(TOKEN)
          put(layer, 'http.request.method', match[1], :string, offset, match[1].bytesize)
          put(layer, 'http.request.uri', match[2], :string, offset + match[1].bytesize + 1, match[2].bytesize)
          put(layer, 'http.request.version', match[3], :string, offset + line.bytesize - match[3].bytesize, match[3].bytesize)
          0
        end
      end

      # @rbs (Layer layer, String bytes, Integer pos, Integer ending) -> Hash[String, Array[String]]
      def parse_headers(layer, bytes, pos, ending)
        # @type var headers: Hash[String, Array[String]]
        headers = {}
        while pos < ending - 2
          after = bytes.index("\r\n", pos) #: Integer
          line = bytes.byteslice(pos, after - pos) #: String
          colon = line.index(':')
          name = colon ? line.byteslice(0, colon) : '' #: String
          unless colon && name.match?(TOKEN)
            layer.diagnose(:error, :malformed, 'invalid HTTP header name')
            return headers
          end
          name = name.downcase
          value = line.byteslice(colon + 1..) #: String
          leading = (value[/\A[ \t]*/n] || '').bytesize
          value = value.sub(/\A[ \t]*/n, '').sub(/(?<![ \t])[ \t]+\z/n, '')
          (headers[name] ||= []) << value
          key = name.tr('-', '_')
          if HEADERS.include?(key)
            numeric = key == 'content_length' && value.match?(/\A[0-9]+\z/n)
            put(layer, "http.#{key}", numeric ? value.to_i : value, numeric ? :uint : :string,
                pos + colon + 1 + leading, value.bytesize)
          else
            put(layer, 'http.request.line', line, :string, pos, line.bytesize)
          end
          layer.diagnose(:error, :malformed, 'control byte in HTTP header') if value.match?(/[\x00-\x08\x0a-\x1f\x7f]/n)
          pos = after + 2
        end
        headers
      end

      # @rbs (Layer layer, String bytes, Integer pos) -> [String, Integer]
      def chunked(layer, bytes, pos)
        body = ''.b
        loop do
          ending = bytes.index("\r\n", pos)
          unless ending
            layer.diagnose(:note, :truncated, 'incomplete HTTP chunk size')
            return [body, bytes.bytesize]
          end
          line = bytes.byteslice(pos, ending - pos) #: String
          size = line.split(';', 2).first || ''
          unless size.match?(/\A[0-9a-fA-F]{1,16}\z/n)
            layer.diagnose(:error, :malformed, 'invalid HTTP chunk size')
            return [body, ending + 2]
          end
          length = size.to_i(16)
          pos = ending + 2
          if length.zero?
            loop do
              ending = bytes.index("\r\n", pos)
              unless ending
                layer.diagnose(:note, :truncated, 'incomplete HTTP trailers')
                return [body, bytes.bytesize]
              end
              return [body, ending + 2] if ending == pos
              put(layer, 'http.chunked.trailer', bytes.byteslice(pos, ending - pos), :string, pos, ending - pos)
              pos = ending + 2
            end
          end
          available = [length, bytes.bytesize - pos].min
          fragment = bytes.byteslice(pos, available) #: String
          body << fragment
          if available < length || pos + length + 2 > bytes.bytesize
            layer.diagnose(:note, :truncated, 'incomplete HTTP chunk')
            return [body, bytes.bytesize]
          end
          unless bytes.byteslice(pos + length, 2) == "\r\n"
            layer.diagnose(:error, :malformed, 'HTTP chunk lacks CRLF')
            return [body, pos + length]
          end
          pos += length + 2
        end
      end

      # @rbs (Layer layer, String name, untyped value, Symbol type, Integer offset, Integer length) -> void
      def put(layer, name, value, type, offset, length)
        layer.add("#{name}_#{layer.definitions.length}".to_sym, name, value, type: type, offset: offset, length: length)
      end

      # @rbs (Layer layer) -> String
      def summary(layer)
        names = layer.field_value('http.request.method') ? %w[http.request.method http.request.uri] : %w[http.response.code http.response.phrase]
        'HTTP ' + names.filter_map { |name| layer.fields.find { |field| field.name == name }&.display }.join(' ')
      end
    end
  end
end
