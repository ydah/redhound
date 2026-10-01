# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module File
    # @api private
    class PcapngWriter
      attr_reader :bytes_written, :path

      # @rbs (untyped output, ?linktype: Integer | Symbol | String, ?snaplen: Integer, ?precision: Symbol, ?packet_buffered: bool, ?filter: String?, ?comment: String?, **untyped) -> void
      def initialize(output, linktype: :ethernet, snaplen: 262_144, precision: :nano, packet_buffered: false,
                     filter: nil, comment: nil, **_options)
        raise ArgumentError, 'snaplen must be between 1 and 16 MiB' unless snaplen.between?(1, Format::MAX_RECORD)

        @linktype, @snaplen, @packet_buffered = Capture::Linktype.resolve(linktype), snaplen, packet_buffered
        @filter, @comment = filter, comment
        @owned = output.is_a?(String) && output != '-'
        @path = output.is_a?(String) ? output : nil
        @io = output.is_a?(String) ? (output == '-' ? $stdout : ::File.open(output, ::File::WRONLY | ::File::CREAT | ::File::TRUNC, 0o600)) : output
        @io.chmod(0o600) if @owned
        @io.binmode if @io.respond_to?(:binmode)
        @bytes_written = 0
        @interfaces, @counts, @start_times, @end_times, @statistics = {}, {}, {}, {}, {}
        @closed = false
        opts = { 3 => RUBY_PLATFORM, 4 => "Redhound #{VERSION}" }
        opts[1] = comment if comment
        write_block(0x0a0d0d0a, [0x1a2b3c4d, 1, 0, 0xffff_ffff_ffff_ffff].pack('VvvQ<') + options(opts))
      end

      # @rbs (Packet packet) -> self
      def write(packet)
        raise IOError, 'writer is closed' if @closed
        raise FileFormatError, 'pcapng timestamp must be nonnegative' if packet.timestamp_ns.negative?

        index = ensure_interface(packet)
        data = packet.data.byteslice(0, @snaplen)
        flags = packet_flags(packet)
        opts = { 2 => [flags].pack('V') }
        opts[1] = packet.meta[:comment].to_s if packet.meta[:comment]
        high, low = packet.timestamp_ns >> 32, packet.timestamp_ns & 0xffff_ffff
        raise FileFormatError, 'pcapng timestamp exceeds unsigned 64-bit range' if high > 0xffff_ffff

        body = [index, high, low, data.bytesize, packet.original_length].pack('V5') + Format.pad(data) + options(opts)
        write_block(6, body)
        @counts[index] = @counts.fetch(index, 0) + 1
        @start_times[index] ||= packet.timestamp_ns
        @end_times[index] = packet.timestamp_ns
        @io.flush if @packet_buffered
        self
      end

      alias << write

      # @rbs (Packet packet) -> Integer
      def record_size(packet)
        44 + Format.padded([packet.caplen, @snaplen].min) + (packet.meta[:comment] ? 4 + Format.padded(packet.meta[:comment].to_s.bytesize) : 0)
      end

      # @rbs (Capture::Stats stats, ?interface: Capture::Interface?) -> void
      def write_stats(stats, interface: nil)
        if interface
          @interfaces.each { |key, index| @statistics[index] = stats if key[0] == interface.object_id }
        elsif @interfaces.size == 1
          @statistics[0] = stats
        elsif @interfaces.size > 1
          # Source statistics describe the entire capture; record them once to avoid double counting.
          @statistics[0] = stats
        end
      end

      # @rbs () -> void
      def flush = @io.flush

      # @rbs () -> void
      def close
        return if @closed

        @interfaces.each_value do |index|
          stats = @statistics[index]
          start_time, end_time = @start_times.fetch(index, 0), @end_times.fetch(index, 0)
          opts = { 2 => timestamp_words(start_time), 3 => timestamp_words(end_time),
                   8 => [@counts.fetch(index, 0)].pack('Q<') }
          if stats
            opts[4], opts[5], opts[7] = [stats.received].pack('Q<'), [stats.dropped].pack('Q<'), [stats.if_dropped].pack('Q<')
            opts[6] = [stats.captured].pack('Q<')
          end
          write_block(5, [index].pack('V') + timestamp_words(end_time) + options(opts))
        end
        @io.flush
        @io.close if @owned
        @closed = true
      end

      private

      # @rbs (Packet packet) -> Integer
      def ensure_interface(packet)
        interface = packet.interface
        key = [interface&.object_id || 0, packet.linktype]
        return @interfaces[key] if @interfaces.key?(key)

        index = @interfaces.size
        @interfaces[key] = index
        opts = { 2 => interface&.name || "interface#{index}", 9 => "\x09".b, 12 => RUBY_PLATFORM }
        opts[3] = interface.description if interface&.description
        expression = interface&.filter || @filter
        opts[11] = "\0" + expression if expression
        write_block(1, [packet.linktype, 0, @snaplen].pack('vvV') + options(opts))
        index
      end

      # @rbs (Packet packet) -> Integer
      def packet_flags(packet)
        direction = { in: 1, out: 2 }.fetch(packet.direction, 0)
        pkttype = packet.meta[:pkttype]
        direction = pkttype == 4 ? 2 : 1 if direction.zero? && pkttype
        reception = { 0 => 1, 1 => 3, 2 => 2, 3 => 4 }.fetch(pkttype, 0)
        direction | (reception << 2)
      end

      # @rbs (Integer timestamp) -> String
      def timestamp_words(timestamp) = [timestamp >> 32, timestamp & 0xffff_ffff].pack('V2')

      # @rbs (Hash[Integer, String] values) -> String
      def options(values)
        values.map do |code, value|
          raise FileFormatError, 'pcapng option exceeds 65535 bytes' if value.bytesize > 65_535

          [code, value.bytesize].pack('vv') + Format.pad(value.b)
        end.join.b + "\0" * 4
      end

      # @rbs (Integer type, String body) -> void
      def write_block(type, body)
        length = body.bytesize + 12
        raise FileFormatError, 'pcapng block exceeds 16 MiB' if length > Format::MAX_RECORD

        @bytes_written += @io.write([type, length].pack('V2') + body + [length].pack('V'))
      end
    end
  end
end
