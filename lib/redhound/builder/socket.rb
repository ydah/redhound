# frozen_string_literal: true

require 'socket'

module Redhound
  module Builder
    class Socket
      SOL_PACKET            = 0x0107 # bits/socket.h
      PACKET_ADD_MEMBERSHIP = 0x0001 # NOTE: netpacket/packet.h
      ETH_P_ALL             = 768    # NOTE: htons(ETH_P_ALL) => linux/if_ether.h
      PACKED_ETH_P_ALL = [ETH_P_ALL].pack('S').unpack1('S>')

      class << self
        def build(ifname:)
          new(ifname:).build
        end
      end

      def initialize(ifname:)
        @mq_req = PacketMreq.new(ifname:)
      end

      def build
        socket = ::Socket.new(::Socket::AF_PACKET, ::Socket::SOCK_RAW, ETH_P_ALL)
        socket.bind([::Socket::AF_PACKET, PACKED_ETH_P_ALL, @mq_req.mr_ifindex].pack('SS>a16'))
        socket.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, @mq_req.build)
        Redhound::Source::Socket.new(socket:)
      end
    end
  end
end
