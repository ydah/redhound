require "socket"

module Redhound
  class PacketMreq
    PACKET_MR_PROMISC = 0x0001 # NOTE: netpacket/packet.h

    def initialize(ifname:)
      @ifname = ifname
    end

    # see: https://man7.org/linux/man-pages/man7/packet.7.html
    # struct packet_mreq {
    #   int            mr_ifindex;    /* interface index */
    #   unsigned short mr_type;       /* action */
    #   unsigned short mr_alen;       /* address length */
    #   unsigned char  mr_address[8]; /* physical-layer address */
    # };
    def generate
      mr_ifindex + mr_type + mr_alen + mr_address
    end

    def mr_ifindex
      @mr_ifindex ||= [[index].pack("c")].pack("a4")
    end

    private

    def index
      ::Socket.getifaddrs.find { |ifaddr| ifaddr.name == @ifname }&.ifindex
    end

    def mr_type
      @mr_type ||= [PACKET_MR_PROMISC].pack("S")
    end

    def mr_alen
      @mr_alen ||= [0].pack("S")
    end

    def mr_address
      @mr_address ||= [0].pack("C") * 8
    end
  end
end
