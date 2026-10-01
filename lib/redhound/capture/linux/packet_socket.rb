# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Linux
      # @api private
      class PacketSocket < Source
        attr_reader :socket, :linktype, :interfaces

        # @rbs (interface: String | Integer | Interface, ?snaplen: Integer, ?promiscuous: bool, ?buffer_size: Integer?, ?direction: Symbol, ?filter: String?) -> void
        def initialize(interface:, snaplen: 262_144, promiscuous: true, buffer_size: nil, direction: :inout, filter: nil)
          super()
          raise ArgumentError, 'snaplen must be between 1 and 16 MiB' unless snaplen.between?(1, File::Format::MAX_RECORD)
          raise ArgumentError, 'direction must be in, out or inout' unless %i[in out inout].include?(direction)

          @interface = interface.is_a?(Interface) ? interface : Interface.find(interface)
          @interfaces = [@interface]
          @snaplen, @direction = snaplen, direction
          @linktype = @interface.linktype
          @cooked = @linktype == 276
          @socket = ::Socket.new(Constants::AF_PACKET, @cooked ? ::Socket::SOCK_DGRAM : ::Socket::SOCK_RAW, 0)
          @interface_drops = interface_dropped
          setup_receive_buffer(buffer_size)
          attach_filter(filter ? Filter.compile(filter, linktype: @linktype, snaplen:, live: true) : nil)
          if promiscuous && @interface.name == 'any'
            warn 'redhound: promiscuous mode is unavailable on any'
          elsif promiscuous
            @socket.setsockopt(Constants::SOL_PACKET, Constants::PACKET_ADD_MEMBERSHIP, [@interface.index, Constants::PACKET_MR_PROMISC, 0, ''.b].pack('i S S a8'))
          end
          @socket.bind(SockaddrLL.new(index: @interface.index).to_sockaddr)
          prime_timestamp
          if direction == :in
            begin
              @socket.setsockopt(Constants::SOL_PACKET, Constants::PACKET_IGNORE_OUTGOING, [1].pack('i'))
            rescue Errno::ENOPROTOOPT, Errno::EINVAL
              # Older kernels are filtered by packet direction below.
            end
          end
        rescue Errno::EPERM, Errno::EACCES => error
          close_resources
          raise PermissionDenied, "capture requires root or CAP_NET_RAW: #{error.message}"
        rescue StandardError
          close_resources
          raise
        end

        # @rbs (?timeout: Numeric?) -> Packet?
        def next_packet(timeout: nil)
          deadline = deadline_for(timeout)
          until @stopped || @closed
            return nil unless wait_readable(@socket, deadline)

            result = @socket.recvfrom_nonblock(Constants::RECEIVE_SIZE, exception: false)
            next if result == :wait_readable

            data, address_info = result
            address = SockaddrLL.parse(address_info.to_sockaddr)
            next unless accept_direction?(address)

            original_length = data.bytesize
            data = Cooked.header(address) + data if @cooked
            original_length += 20 if @cooked
            timestamp_ns = timestamp
            meta = { pkttype: address.pkttype, csum_not_ready: address.hatype == 772 || address.pkttype == Constants::PACKET_OUTGOING }
            meta[:possible_truncation] = true if original_length >= Constants::RECEIVE_SIZE + (@cooked ? 20 : 0)
            @number += 1
            @capture_stats.captured += 1
            return Packet.new(data.byteslice(0, @snaplen), timestamp_ns:, original_length:, linktype: @linktype,
                              interface: packet_interface(address), direction: address.pkttype == Constants::PACKET_OUTGOING ? :out : :in, number: @number, meta:)
          end
          nil
        end

        # @rbs (untyped program) -> void
        def attach_filter(program)
          instructions = program ? program.instructions : [[0x06, 0, 0, receive_snaplen]] #: Array[[Integer, Integer, Integer, Integer]]
          Filter::BPF::Validator.validate!(instructions)
          instructions = instructions.map do |instruction|
            code, jt, jf, k = instruction #: [Integer, Integer, Integer, Integer]
            [code, jt, jf, code == 0x06 && k.positive? ? receive_snaplen : k]
          end
          packed = instructions.map { |instruction| instruction.pack('S C C L') }.join
          @socket.setsockopt(::Socket::SOL_SOCKET, Constants::SO_ATTACH_FILTER, [instructions.size, packed].pack('S x6 P'))
        end

        # @rbs () -> Stats
        def stats
          unless @closed
            counters = @socket.getsockopt(Constants::SOL_PACKET, Constants::PACKET_STATISTICS).data.unpack('L*')
            @capture_stats.received += counters.fetch(0, 0)
            @capture_stats.dropped += counters.fetch(1, 0)
            @capture_stats.freeze_count += counters.fetch(2, 0)
            @capture_stats.if_dropped = [interface_dropped - @interface_drops, 0].max
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
            close_resources
          end
        end

        protected

        # @rbs () -> void
        def close_resources
          @socket.close if @socket && !@socket.closed?
        end

        # @rbs () -> void
        def prime_timestamp
          @socket.ioctl(Constants::SIOCGSTAMPNS, "\0" * 16)
        rescue Errno::ENOENT, Errno::ENOTTY, Errno::EINVAL
          nil
        end

        # @rbs () -> Integer
        def receive_snaplen = Constants::RECEIVE_SIZE

        # @rbs (Integer? buffer_size) -> void
        def setup_receive_buffer(buffer_size)
          return unless buffer_size
          raise ArgumentError, 'buffer size must be positive' unless buffer_size.positive?

          @socket.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_RCVBUF, [buffer_size].pack('i'))
          begin
            @socket.setsockopt(::Socket::SOL_SOCKET, Constants::SO_RCVBUFFORCE, [buffer_size].pack('i'))
          rescue Errno::EPERM, Errno::EACCES, Errno::ENOPROTOOPT
            # SO_RCVBUF already applied without CAP_NET_ADMIN.
          end
        end

        # @rbs (SockaddrLL address) -> bool
        def accept_direction?(address)
          outgoing = address.pkttype == Constants::PACKET_OUTGOING
          return false if outgoing && address.hatype == 772 && @direction != :out

          @direction == :inout || (@direction == :out) == outgoing
        end

        # @rbs (SockaddrLL address) -> Interface
        def packet_interface(address)
          return @interface unless @interface.name == 'any'

          @any_interfaces ||= Interface.all.to_h { |interface| [interface.index, interface] }
          @any_interfaces.fetch(address.index) { Interface.new(name: "if#{address.index}", index: address.index, linktype: 276) }
        end

        # @rbs () -> Integer
        def interface_dropped
          return 0 if @interface.name == 'any'

          ::File.read("/sys/class/net/#{@interface.name}/statistics/rx_dropped").to_i
        rescue Errno::ENOENT, Errno::EACCES
          0
        end

        # @rbs () -> Integer
        def timestamp
          buffer = "\0" * 16
          @socket.ioctl(Constants::SIOCGSTAMPNS, buffer)
          seconds, nanos = buffer.unpack('q q') #: [Integer, Integer]
          seconds * 1_000_000_000 + nanos
        rescue Errno::ENOENT, Errno::ENOTTY, Errno::EINVAL
          Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond)
        end
      end
    end
  end
end
