# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    class FileSource < Source
      class ReadStopped < StandardError; end

      # Nonregular inputs need bounded polling so Source#stop can interrupt an idle pipe.
      class StreamInput
        # @rbs (IO io, Source source) -> void
        def initialize(io, source)
          @io, @source = io, source
        end

        # @rbs (Integer length) -> String?
        def read(length)
          loop do
            raise ReadStopped if @source.stopped?
            next unless IO.select([@io], nil, nil, 0.1)

            part = @io.read_nonblock(length, exception: false)
            next if part == :wait_readable

            return part
          end
        end
      end

      attr_reader :reader

      # @rbs (untyped input, ?filter: String?) -> void
      def initialize(input, filter: nil)
        super()
        @owned = input.is_a?(String) && input != '-'
        @io = input.is_a?(String) ? (input == '-' ? $stdin : ::File.open(input, 'rb')) : input
        @io.binmode if @io.respond_to?(:binmode)
        reader_io = @io.is_a?(IO) && !@io.stat.file? ? StreamInput.new(@io, self) : @io
        @stream = reader_io.is_a?(StreamInput)
        @packets = nil # @rbs Thread::SizedQueue[Packet | StandardError]?
        @reader_thread = nil # @rbs Thread?
        magic = File::Format.read_exact(reader_io, 4)
        @reader = if magic == File::Format::PCAPNG_MAGIC
                    File::PcapngReader.new(reader_io, magic)
                  elsif File::Format::PCAP_MAGICS.key?(magic)
                    File::PcapReader.new(reader_io, magic)
                  else
                    raise FileFormatError, 'unrecognized capture file magic'
                  end
        @filter_expression = filter
        @filter_program = nil # @rbs Filter::Program?
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

        deadline = deadline_for(timeout)
        polled = false
        until @stopped || @closed
          return nil if polled && deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
          polled = true
          remaining = deadline && [deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0].max
          packet = read_packet(remaining)
          return nil if packet == :wait_readable
          break unless packet

          @capture_stats.received += 1
          next if @filter_program && !@filter_program.match?(packet)
          if @filter_expression
            program = (@filters[packet.linktype] ||= Filter.compile(@filter_expression, linktype: packet.linktype))
            next unless program.match?(packet)
          end
          @capture_stats.captured += 1
          return packet
        end
        stop
        nil
      rescue ReadStopped
        nil
      end

      # @rbs (Filter::Program? program) -> void
      def attach_filter(program)
        @filter_expression = nil
        @filters.clear
        @filter_program = program
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
      def stop
        super
        @packets&.close
      end

      # @rbs () -> void
      def close
        return if @closed

        super
        @reader_thread&.join(0.2)
        @io.close if @owned
      end

      private

      # A single bounded worker preserves partial records across caller timeouts.
      # @rbs (Numeric? timeout) -> (Packet | nil | :wait_readable)
      def read_packet(timeout)
        return @reader.next_packet unless @stream

        unless @packets
          queue = Thread::SizedQueue.new(1) #: Thread::SizedQueue[Packet | StandardError]
          @packets = queue
          @reader_thread = Thread.new do
            begin
              while !stopped? && (packet = @reader.next_packet)
                queue << packet
              end
            rescue ReadStopped, ClosedQueueError
              nil
            rescue StandardError => error
              begin
                queue << error
              rescue ClosedQueueError
                nil
              end
            ensure
              queue.close
            end
          end
        end
        queue = @packets #: Thread::SizedQueue[Packet | StandardError]
        result = queue.pop(timeout: timeout && Float(timeout))
        raise result if result.is_a?(StandardError)

        return result if result
        return nil if queue.closed?

        :wait_readable
      end
    end
  end
end
