# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # A stateful TCP dissector. Instances belong to one bidirectional flow.
  # Override on_data/on_gap for custom stream protocols; built-in framing is
  # shared with the packet dissectors so validation has one implementation.
  class StreamDissector < Dissector
    # @rbs (?registry: Registry, ?max_bytes: Integer) -> void
    def initialize(registry: Registry.default, max_bytes: 1 << 20)
      @registry, @max_bytes = registry, max_bytes
      @buffers = [''.b, ''.b]
      @origins = [Array.new, Array.new] #: Array[untyped]
      @tls_encrypted = [false, false]
    end

    # @rbs (untyped stream, Integer direction, String data, Integer frame) -> Array[Layer]
    def on_data(stream, direction, data, frame)
      @buffers[direction] << data
      @origins[direction] << [data.bytesize, frame] unless data.empty?
      if bytesize > @max_bytes
        on_gap(stream, direction, @buffers[direction].bytesize)
        return [Layer.new(self.class.protocol_id, 0, 0, 0).diagnose(:warning, :reassembly_gap, 'stream PDU buffer limit exceeded')]
      end
      layers = [] #: Array[Layer]
      loop do
        buffer = @buffers[direction]
        length = pdu_length(buffer, direction)
        break unless length && length.positive?
        layer = parse_pdu(buffer.byteslice(0, length), tls_encrypted: @tls_encrypted[direction])
        @tls_encrypted[direction] = true if self.class.protocol_id == :tls && layer.field_values('tls.record.content_type').include?(20)
        layer.add(:reassembled_from, 'tcp.reassembled_from', consume_origins(direction, length))
        layers << layer
        @buffers[direction] = buffer.byteslice(length..) || ''.b
      end
      layers
    end

    # @rbs (untyped stream, Integer direction, Integer length) -> Array[Layer]
    def on_gap(stream, direction, length)
      @buffers[direction].clear
      @origins[direction].clear
      []
    end

    # @rbs (untyped stream, Integer direction) -> Array[Layer]
    def on_close(stream, direction)
      buffer = @buffers[direction]
      return [] if buffer.empty?
      layer = parse_pdu(buffer, tls_encrypted: @tls_encrypted[direction])
      layer.add(:reassembled_from, 'tcp.reassembled_from', consume_origins(direction, buffer.bytesize))
      @buffers[direction] = ''.b
      [layer]
    end

    # @rbs () -> Integer
    def bytesize = @buffers.sum(&:bytesize) + @origins.sum { |origins| origins.size * 64 }

    # @rbs (Integer direction, Integer length) -> Array[Integer]
    def consume_origins(direction, length)
      frames = [] #: Array[Integer]
      while length.positive? && !@origins[direction].empty?
        size, frame = @origins[direction].first
        frames << frame
        if size > length
          @origins[direction][0] = [size - length, frame]
          length = 0
        else
          @origins[direction].shift
          length -= size
        end
      end
      frames.uniq.sort
    end

    # @rbs (String bytes, ?tls_encrypted: bool) -> Layer
    def parse_pdu(bytes, tls_encrypted: false)
      packet = Packet.new(bytes, meta: { tls_encrypted: tls_encrypted })
      ctx = Context.new(packet, registry: @registry)
      ctx.layers << Layer.new(:tcp, 0, 0, bytes.bytesize)
      Engine.new(registry: @registry).safely(self.class, ctx, ctx.cursor)
    end

    # @rbs (String buffer, ?Integer direction) -> Integer?
    def pdu_length(buffer, direction = 0)
      case self.class.protocol_id
      when :dns
        return nil if buffer.bytesize < 2
        length = buffer.unpack1('n') #: Integer
        buffer.bytesize >= length + 2 ? length + 2 : nil
      when :http then http_length(buffer)
      when :tls then tls_length(buffer, direction)
      else buffer.empty? ? nil : buffer.bytesize
      end
    end

    # @rbs (String buffer) -> Integer?
    def http_length(buffer)
      ending = buffer.index("\r\n\r\n")
      return buffer.bytesize if !ending && buffer.bytesize > 65_536
      return nil unless ending
      head_end = ending + 4
      header = buffer.byteslice(0, ending) #: String
      response = header.start_with?('HTTP/')
      status = response ? header.split(' ', 3)[1].to_i : 0
      return head_end if response && (status.between?(100, 199) || [204, 304].include?(status))
      lengths = header.scan(/\r\ncontent-length:[ \t]*([^\r\n]*)/in).flatten.flat_map { |value| value.split(',').map(&:strip) }
      transfer = header.scan(/\r\ntransfer-encoding:[ \t]*([^\r\n]*)/in).flatten.join(',').downcase.split(',').map(&:strip)
      if (!lengths.empty? && !transfer.empty?) || lengths.uniq.size > 1 || lengths.any? { |value| !value.match?(/\A[0-9]+\z/n) }
        return head_end # The packet parser reports conflicting or invalid framing.
      end
      if transfer.last == 'chunked'
        layer = Layer.new(:http, 0, 0, buffer.bytesize)
        parser = self #: untyped
        _body, pos = parser.chunked(layer, buffer, head_end)
        return nil if layer.diagnostics.any? { |diagnostic| diagnostic.code == :truncated }
        return pos
      end
      return response ? nil : head_end unless transfer.empty?
      unless lengths.empty?
        length = head_end + lengths[0].to_i
        return length <= buffer.bytesize ? length : nil
      end
      response ? nil : head_end
    end

    # @rbs (String buffer, Integer direction) -> Integer?
    def tls_length(buffer, direction)
      pos = 0
      while pos + 5 <= buffer.bytesize
        parts = buffer.unpack('Cnn', offset: pos) #: [Integer, Integer, Integer]
        type, version, length = parts
        return pos + 5 unless type.between?(20, 24) && version.between?(0x0300, 0x0303) && length <= 18_432
        break if pos + 5 + length > buffer.bytesize
        pos += 5 + length
      end
      return nil if pos.zero?
      bytes = buffer.byteslice(0, pos) #: String
      candidate = parse_pdu(bytes, tls_encrypted: @tls_encrypted[direction])
      candidate.diagnostics.any? { |diagnostic| diagnostic.code == :truncated } ? nil : pos
    end
  end
end
