require 'socket'

module Redhound
  class SocketBuilder
    class << self
      def build(ifname:)
        new(ifname:).build
      end
    end

    SOL_PACKET            = 0x0107 # bits/socket.h
    PACKET_ADD_MEMBERSHIP = 0x0001 # NOTE: netpacket/packet.h
    ETH_P_ALL             = 768    # NOTE: htons(ETH_P_ALL) => linux/if_ether.h
    PACKED_ETH_P_ALL = [ETH_P_ALL].pack('S').unpack('S>').first

    def initialize(ifname:)
      @ifname = ifname
      @mq_req = PacketMreq.new(ifname: @ifname)
    end

    def build
      socket = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
      socket.bind([Socket::AF_PACKET, PACKED_ETH_P_ALL, @mq_req.mr_ifindex].pack('SS>a16'))
      socket.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, @mq_req.generate)
      socket
    end
  end
end
