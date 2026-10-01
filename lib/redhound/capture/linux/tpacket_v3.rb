# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Linux
      # @api private
      class TPacketV3 < PacketSocket
        # @rbs (?timeout: Numeric?) -> Packet?
        def next_packet(timeout: nil)
          deadline = deadline_for(timeout)
          until @stopped || @closed
            unless @pending_count.positive?
              base = @current_block * @block_size
              unless (u32(base + 8) & Constants::TP_STATUS_USER).positive?
                return nil unless wait_readable(@socket, deadline)
                next
              end
              @block_end = base + u32(base + 20)
              @pending_count = u32(base + 12)
              @packet_offset = base + u32(base + 16)
              if @pending_count.zero?
                release_block
                next
              end
            end

            offset = @packet_offset
            check_ring_bounds(offset, 68)
            next_offset, seconds, nanos, caplen, original_length, status = @ring.get_string(offset, 24).unpack('L6')
            mac_offset = @ring.get_value(:u16, offset + 24)
            check_ring_bounds(offset + mac_offset, caplen)
            data = @ring.get_string(offset + mac_offset, caplen)
            address = SockaddrLL.parse(@ring.get_string(offset + 48, 20))
            meta = { pkttype: address.pkttype, csum_not_ready: (status & Constants::TP_STATUS_CSUMNOTREADY).positive?,
                     csum_valid: (status & Constants::TP_STATUS_CSUM_VALID).positive? }
            if (status & Constants::TP_STATUS_VLAN_VALID).positive?
              tci = u32(offset + 32) & 0xffff
              tpid = (status & Constants::TP_STATUS_VLAN_TPID_VALID).positive? ? @ring.get_value(:u16, offset + 36) : 0x8100
              meta[:vlan_tci], meta[:vlan_tpid] = tci, tpid
              if !@cooked && @linktype == 1
                original_length += 4
                data = data.byteslice(0, 12) + [tpid, tci].pack('n2') + data.byteslice(12..) if data.bytesize >= 12
              elsif @cooked
                data = [tci, address.protocol].pack('n2') + data
                original_length += 4
                address = SockaddrLL.new(protocol: tpid, index: address.index, hatype: address.hatype,
                                         pkttype: address.pkttype, address: address.address)
              end
            end
            if @cooked
              data = Cooked.header(address) + data
              original_length += 20
            end
            @pending_count -= 1
            if @pending_count.zero?
              release_block
            else
              raise CaptureError, 'invalid ring packet offset' if next_offset < 68
              @packet_offset += next_offset
            end
            next unless accept_direction?(address)

            @number += 1
            @capture_stats.captured += 1
            return Packet.new(data.byteslice(0, @snaplen), timestamp_ns: seconds * 1_000_000_000 + nanos,
                              original_length:, linktype: @linktype, interface: packet_interface(address),
                              direction: address.pkttype == Constants::PACKET_OUTGOING ? :out : :in, number: @number, meta:)
          end
          nil
        end

        protected

        # @rbs () -> void
        def close_resources
          begin
            @ring.free if @ring
          ensure
            @ring = nil
            super
          end
        end

        # @rbs () -> Integer
        def receive_snaplen = @cooked ? [@snaplen - 20, 1].max : @snaplen

        # @rbs (Integer? buffer_size) -> void
        def setup_receive_buffer(buffer_size)
          raise ArgumentError, 'buffer size must be positive' if buffer_size && !buffer_size.positive?

          @block_size = 1 << 20
          @block_size *= 2 while @block_size < @snaplen + 128
          @block_count = buffer_size ? [(buffer_size.to_f / @block_size).ceil, 1].max : 8
          frame_size = 2048
          request = [@block_size, @block_count, frame_size, @block_size * @block_count / frame_size, 50, 0, 0].pack('L7')
          @socket.setsockopt(Constants::SOL_PACKET, Constants::PACKET_VERSION, [Constants::TPACKET_V3].pack('i'))
          @socket.setsockopt(Constants::SOL_PACKET, Constants::PACKET_RX_RING, request)
          experimental = Warning[:experimental]
          begin
            Warning[:experimental] = false
            @ring = IO::Buffer.map(@socket, @block_size * @block_count, 0)
          ensure
            Warning[:experimental] = experimental
          end
          @current_block, @pending_count, @packet_offset, @block_end = 0, 0, 0, 0
        end

        private

        # @rbs (Integer offset) -> Integer
        def u32(offset) = @ring.get_value(:u32, offset)

        # @rbs (Integer offset, Integer length) -> void
        def check_ring_bounds(offset, length)
          unless offset >= @current_block * @block_size && length >= 0 && offset + length <= @block_end && @block_end <= (@current_block + 1) * @block_size
            raise CaptureError, 'invalid ring packet bounds'
          end
        end

        # @rbs () -> void
        def release_block
          @ring.set_value(:u32, @current_block * @block_size + 8, 0)
          @current_block = (@current_block + 1) % @block_count
          @pending_count = 0
        end
      end
    end
  end
end
