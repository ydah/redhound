# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    class FileSource < Source
      attr_reader :reader

      # @rbs (untyped input, ?filter: String?) -> void
      def initialize(input, filter: nil)
        super()
        @owned = input.is_a?(String) && input != '-'
        @io = input.is_a?(String) ? (input == '-' ? $stdin : ::File.open(input, 'rb')) : input
        @io.binmode if @io.respond_to?(:binmode)
        magic = File::Format.read_exact(@io, 4)
        @reader = if magic == File::Format::PCAPNG_MAGIC
                    File::PcapngReader.new(@io, magic)
                  elsif File::Format::PCAP_MAGICS.key?(magic)
                    File::PcapReader.new(@io, magic)
                  else
                    raise FileFormatError, 'unrecognized capture file magic'
                  end
        @filter_expression = filter
        @filters = {} #: Hash[Integer, untyped]
        @filters[@reader.linktype] = Filter.compile(filter, linktype: @reader.linktype) if filter
      rescue StandardError, Interrupt
        @io.close if @owned && @io && !@io.closed?
        raise
      end

      # @rbs (untyped input, ?filter: String?) -> FileSource
      # @rbs [T] (untyped input, ?filter: String?) { (FileSource) -> T } -> T
      def self.open(input, filter: nil)
        source = new(input, filter:)
        return source unless block_given?

        begin
          yield source
        ensure
          source.close
        end
      end

      # @rbs (?timeout: Numeric?) -> Packet?
      def next_packet(timeout: nil)
        return nil if @stopped || @closed

        while (packet = @reader.next_packet)
          @capture_stats.received += 1
          if @filter_expression
            program = (@filters[packet.linktype] ||= Filter.compile(@filter_expression, linktype: packet.linktype))
            next unless program.match?(packet)
          end
          @capture_stats.captured += 1
          return packet
        end
        stop
        nil
      end

      # @rbs () -> Integer
      def linktype = @reader.linktype

      # @rbs () -> Array[Interface]
      def interfaces = @reader.interfaces

      # @rbs () -> Stats
      def stats
        @reader.respond_to?(:statistics?) && @reader.statistics? ? @reader.stats : super
      end

      # @rbs () -> void
      def close
        return if @closed

        super
        @io.close if @owned
      end
    end
  end
end
