# rbs_inline: enabled
# frozen_string_literal: true

require 'shellwords'

module Redhound
  # @api private
  module File
    # @api private
    class RotatingWriter
      attr_reader :path

      # @rbs (String path, ?max_bytes: Integer?, ?interval: Numeric?, ?file_count: Integer?, ?post_rotate_command: String?, **untyped options) -> void
      def initialize(path, max_bytes: nil, interval: nil, file_count: nil, post_rotate_command: nil, **options)
        raise ArgumentError, 'cannot rotate standard output' if path == '-'
        raise ArgumentError, 'max_bytes must be positive' if max_bytes && max_bytes <= 0
        raise ArgumentError, 'interval must be positive' if interval && interval <= 0
        raise ArgumentError, 'file_count must be positive' if file_count && file_count <= 0

        @base, @max_bytes, @interval, @file_count = path, max_bytes, interval, file_count
        @post_rotate_command, @options = post_rotate_command && Shellwords.split(post_rotate_command), options
        raise ArgumentError, 'post-rotate command must not be empty' if @post_rotate_command&.empty?
        @sequence, @packet_count, @closed = 0, 0, false
        open_next
      end

      # @rbs (Packet packet) -> self
      def write(packet)
        raise IOError, 'writer is closed' if @closed

        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - @opened_at
        size_due = @max_bytes && @writer.bytes_written >= @max_bytes
        time_due = @interval && elapsed >= @interval
        rotate if @packet_count.positive? && (size_due || time_due)
        @writer.write(packet)
        @packet_count += 1
        self
      end

      alias << write

      # @rbs (Capture::Stats stats, ?interface: Capture::Interface?) -> void
      def write_stats(stats, interface: nil) = @writer.write_stats(stats, interface:)

      # @rbs () -> Integer
      def bytes_written = @writer.bytes_written

      # @rbs () -> void
      def flush = @writer.flush

      # @rbs () -> void
      def close
        return if @closed

        @writer.close
        run_command
        @closed = true
      end

      private

      # @rbs () -> void
      def rotate
        @writer.close
        run_command
        @closed = true
        @sequence += 1
        if @interval && !@max_bytes && @file_count && @sequence >= @file_count
          @closed = true
          raise RotationComplete, 'rotation file count reached'
        end
        open_next
      end

      # @rbs () -> void
      def open_next
        sequence = @max_bytes && @file_count ? @sequence % @file_count : @sequence
        base = @interval ? Time.now.strftime(@base) : @base
        extension = ::File.extname(base)
        stem = extension.empty? ? base : base.delete_suffix(extension)
        @path = "#{stem}_#{format('%05d', sequence)}#{extension}"
        @writer = Writer.open(@path, **@options)
        @opened_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        @packet_count = 0
        @closed = false
      end

      # @rbs () -> void
      def run_command
        return unless @post_rotate_command

        pid = Process.spawn(*@post_rotate_command, @path)
        _, status = Process.wait2(pid)
        raise CaptureError, "post-rotate command failed: #{status.exitstatus}" unless status.success?
      end
    end
  end
end
