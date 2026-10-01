# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module File
    # @api private
    class PcapWriter
      attr_reader :bytes_written, :path

      # @rbs (untyped output, ?linktype: Integer | Symbol | String, ?snaplen: Integer, ?precision: Symbol, ?packet_buffered: bool, **untyped) -> void
      def initialize(output, linktype: :ethernet, snaplen: 262_144, precision: :nano, packet_buffered: false, **_options)
        raise ArgumentError, 'snaplen must be between 1 and 16 MiB' unless snaplen.between?(1, Format::MAX_RECORD)
        raise ArgumentError, 'precision must be micro or nano' unless %i[micro nano].include?(precision)

        @linktype = Capture::Linktype.resolve(linktype)
        @snaplen, @precision, @packet_buffered = snaplen, precision, packet_buffered
        @owned = output.is_a?(String) && output != '-'
        @path = output.is_a?(String) ? output : nil
        @io = output.is_a?(String) ? (output == '-' ? $stdout : ::File.open(output, ::File::WRONLY | ::File::CREAT | ::File::TRUNC, 0o600)) : output
        @io.chmod(0o600) if @owned
        @io.binmode if @io.respond_to?(:binmode)
        @bytes_written = 0
        @closed = false
        magic = precision == :nano ? 0xa1b23c4d : 0xa1b2c3d4
        write_bytes([magic, 2, 4, 0, 0, snaplen, @linktype].pack('VvvV4'))
      end

      # @rbs (Packet packet) -> self
      def write(packet)
        raise IOError, 'writer is closed' if @closed
        raise FileFormatError, 'pcap cannot store multiple link types; use pcapng' unless packet.linktype == @linktype

        seconds, nanos = packet.timestamp_ns.divmod(1_000_000_000)
        raise FileFormatError, 'pcap timestamp exceeds unsigned 32-bit seconds' unless seconds.between?(0, 0xffff_ffff)

        data = packet.data.byteslice(0, @snaplen)
        fraction = @precision == :nano ? nanos : nanos / 1_000
        write_bytes([seconds, fraction, data.bytesize, packet.original_length].pack('V4') + data)
        @io.flush if @packet_buffered
        self
      end

      alias << write

      # @rbs (Packet packet) -> Integer
      def record_size(packet) = 16 + [packet.caplen, @snaplen].min

      # @rbs (Capture::Stats stats, ?interface: Capture::Interface?) -> void
      def write_stats(stats, interface: nil); end

      # @rbs () -> void
      def flush = @io.flush

      # @rbs () -> void
      def close
        return if @closed

        @io.flush
        @io.close if @owned
        @closed = true
      end

      private

      # @rbs (String bytes) -> void
      def write_bytes(bytes)
        @bytes_written += @io.write(bytes)
      end
    end
  end
end
