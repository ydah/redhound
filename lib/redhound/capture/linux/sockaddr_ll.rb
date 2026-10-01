# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Linux
      # @api private
      class SockaddrLL
        attr_reader :protocol, :index, :hatype, :pkttype, :address

        # @rbs (?protocol: Integer, ?index: Integer, ?hatype: Integer, ?pkttype: Integer, ?address: String) -> void
        def initialize(protocol: Constants::ETH_P_ALL, index: 0, hatype: 0, pkttype: 0, address: ''.b)
          @protocol, @index, @hatype, @pkttype, @address = protocol, index, hatype, pkttype, address.byteslice(0, 8)
        end

        # @rbs () -> String
        def to_sockaddr
          [Constants::AF_PACKET, @protocol, @index, @hatype, @pkttype, @address.bytesize, @address].pack('S n l S C C a8')
        end

        # @rbs (String bytes) -> SockaddrLL
        def self.parse(bytes)
          raise CaptureError, 'truncated sockaddr_ll' if bytes.bytesize < 20

          _family, protocol, index, hatype, pkttype, length, address = bytes.unpack('S n l S C C a8') #: [Integer, Integer, Integer, Integer, Integer, Integer, String]
          new(protocol:, index:, hatype:, pkttype:, address: address.byteslice(0, [length, 8].min) || ''.b)
        end
      end
    end
  end
end
