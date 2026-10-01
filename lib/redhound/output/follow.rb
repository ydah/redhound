# rbs_inline: enabled
# frozen_string_literal: true

require 'tempfile'

module Redhound
  # @api private
  module Output
    # @api private
    class Follow
      # @rbs (String specification) -> void
      def initialize(specification)
        match = /\Atcp,(ascii|hex|raw),(\d+)\z/.match(specification)
        raise ConfigurationError, 'follow must be tcp,ascii|hex|raw,N' unless match
        @format, @stream_id, @offsets = match[1], match[2].to_i, [0, 0]
        @file = Tempfile.new(['redhound-follow-', '.bin'])
        @file.binmode
        @key = nil # @rbs untyped
      end
      # @rbs (Analysis::Flow flow, Integer direction, String data) -> void
      def write(flow, direction, data)
        return unless flow.id == @stream_id && !data.empty?
        @key ||= flow.key
        @file.write([direction, data.bytesize].pack('CN'))
        @file.write(data)
      end
      # @rbs (untyped io) -> void
      def format(io)
        @file.rewind
        unless @format == 'raw'
          io.puts("TCP stream #{@stream_id} (#{@format})")
          if @key
            io.puts("Node 0: #{@key[1]}:#{@key[2]}")
            io.puts("Node 1: #{@key[3]}:#{@key[4]}")
          end
        end
        while (header = @file.read(5))
          direction, length = header.unpack('CN')
          data = @file.read(length) #: String
          case @format
          when 'raw' then io.write(data)
          when 'ascii'
            io.write(direction.zero? ? '' : "\t")
            io.write(data.gsub(/[^\x20-\x7e\r\n\t]/n) { |byte| Kernel.format('\\x%02x', byte.getbyte(0)) })
          when 'hex'
            data.bytes.each_slice(16) do |bytes|
              io.puts(Kernel.format('%s%08x  %s', direction.zero? ? '' : "\t", @offsets[direction], bytes.map { |byte| Kernel.format('%02x', byte) }.join(' ')))
              @offsets[direction] += bytes.size
            end
          end
        end
      ensure
        close
      end
      # @rbs () -> void
      def close = @file.close!
    end
  end
end
