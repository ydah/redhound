# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Bsd
      # @api private
      class BpfDevice < Source
        attr_reader :linktype, :interfaces

        # @rbs (interface: String | Integer | Interface, ?snaplen: Integer, ?promiscuous: bool, ?buffer_size: Integer?, ?direction: Symbol, ?filter: String?) -> void
        def initialize(interface:, snaplen: 262_144, promiscuous: true, buffer_size: nil, direction: :inout, filter: nil)
          super()
          raise ArgumentError, 'snaplen must be between 1 and 16 MiB' unless snaplen.between?(1, File::Format::MAX_RECORD)
          raise ArgumentError, 'direction must be in, out or inout' unless %i[in out inout].include?(direction)

          @interface = interface.is_a?(Interface) ? interface : Interface.find(interface)
          raise UnsupportedPlatform, 'any capture is only available on Linux' if @interface.name == 'any'

          @snaplen, @direction = snaplen, direction
          @device = open_device
          if buffer_size
            raise ArgumentError, 'buffer size must be positive' unless buffer_size.positive?
            @device.ioctl(Constants::BIOCSBLEN, [buffer_size].pack('I'))
          end
          @device.ioctl(Constants::BIOCSETIF, [@interface.name].pack('a16') + "\0" * 16)
          buffer = "\0" * 4
          @device.ioctl(Constants::BIOCGBLEN, buffer)
          @buffer_size = buffer.unpack1('I')
          @device.ioctl(Constants::BIOCGDLT, buffer)
          dlt = buffer.unpack1('I')
          @linktype = dlt == 12 ? 101 : dlt
          @interfaces = [Interface.new(name: @interface.name, index: @interface.index, flags: @interface.flags,
                                       linktype: @linktype, snaplen:)]
          attach_filter(filter ? Filter.compile(filter, linktype: @linktype, snaplen:) : nil)
          @device.ioctl(Constants::BIOCPROMISC, 0) if promiscuous && !@interface.loopback?
          @device.ioctl(Constants::BIOCIMMEDIATE, [1].pack('I'))
          configure_direction
          @device.ioctl(Constants::BIOCFLUSH, 0)
          @records, @offset = ''.b, 0
        rescue Errno::EPERM, Errno::EACCES => error
          @device&.close
          raise PermissionDenied, "capture requires access to /dev/bpf*: #{error.message}"
        rescue StandardError
          @device&.close
          raise
        end

        # @rbs (?timeout: Numeric?) -> Packet?
        def next_packet(timeout: nil)
          deadline = deadline_for(timeout)
          polled = false
          until @stopped || @closed
            return nil if polled && deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
            polled = true
            if @offset >= @records.bytesize
              return nil unless wait_readable(@device, deadline)
              result = @device.read_nonblock(@buffer_size, exception: false)
              next if result == :wait_readable
              return nil unless result

              @records, @offset = result, 0
              next if @records.empty?
            end
            raise CaptureError, 'truncated BPF record header' if @offset + 18 > @records.bytesize

            seconds, micros, caplen, original_length, header_length = @records.unpack('I4S', offset: @offset)
            unless header_length >= 18 && caplen <= original_length && @offset + header_length + caplen <= @records.bytesize
              raise CaptureError, 'invalid BPF record length'
            end
            direction = if @extended_header && header_length >= 20
                          (@records.getbyte(@offset + 19) & 1).positive? ? :out : :in
                        elsif @direction != :inout
                          @direction
                        end
            data = @records.byteslice(@offset + header_length, [caplen, @snaplen].min)
            @offset += (header_length + caplen + 3) & ~3
            @number += 1
            @capture_stats.captured += 1
            return Packet.new(data, timestamp_ns: seconds * 1_000_000_000 + micros * 1_000,
                              original_length:, linktype: @linktype, interface: @interfaces.first, direction:, number: @number,
                              meta: { csum_not_ready: direction == :out })
          end
          nil
        end

        # @rbs (untyped program) -> void
        def attach_filter(program)
          instructions = program ? program.instructions : [[0x06, 0, 0, @snaplen]] #: Array[[Integer, Integer, Integer, Integer]]
          Filter::BPF::Validator.validate!(instructions)
          raise FilterTooLarge, 'macOS BPF programs are limited to 512 instructions' if instructions.size > 512
          packed = instructions.map { |instruction| instruction.pack('S C C L') }.join
          @device.ioctl(Constants::BIOCSETF, [instructions.size, packed].pack('L x4 P'))
        end

        # @rbs () -> Stats
        def stats
          unless @closed
            buffer = "\0" * 8
            @device.ioctl(Constants::BIOCGSTATS, buffer)
            @capture_stats.received, @capture_stats.dropped = buffer.unpack('I2')
          end
          @capture_stats
        end

        # @rbs () -> void
        def close
          return if @closed

          begin
            stats
          ensure
            super
            @device.close
          end
        end

        private

        # @rbs () -> ::File
        def open_device
          256.times do |index|
            begin
              return ::File.open("/dev/bpf#{index}", ::File::RDWR)
            rescue Errno::EBUSY
              next
            rescue Errno::ENOENT
              break
            end
          end
          raise CaptureError, 'no available BPF device'
        end

        # @rbs () -> void
        def configure_direction
          begin
            @device.ioctl(Constants::BIOCSDIRECTION, [{ in: 1, out: 2, inout: 3 }.fetch(@direction)].pack('I'))
          rescue Errno::EINVAL, Errno::ENOTTY
            raise UnsupportedPlatform, 'outgoing-only capture is unavailable on this macOS version' if @direction == :out

            @device.ioctl(Constants::BIOCSSEESENT, [@direction == :in ? 0 : 1].pack('I'))
          end
          begin
            @device.ioctl(Constants::BIOCSEXTHDR, [1].pack('I'))
            @extended_header = true
          rescue Errno::EINVAL, Errno::ENOTTY
            @extended_header = false
          end
        end
      end
    end
  end
end
