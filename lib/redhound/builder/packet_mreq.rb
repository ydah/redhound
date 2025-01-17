# rbs_inline: enabled
# frozen_string_literal: true

require 'socket'

module Redhound
  module Builder
    class PacketMreq
      PACKET_MR_PROMISC = 0x0001 # NOTE: netpacket/packet.h

      # @rbs (ifname: String) -> void
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
      # @rbs () -> String
      def build
        mr_ifindex + mr_type + mr_alen + mr_address
      end

      # @rbs () -> String
      def mr_ifindex
        @mr_ifindex ||= [[index].pack('I')].pack('a4')
      end

      private

      # @rbs () -> Integer?
      def index
        ::Socket.getifaddrs.find { |ifaddr| ifaddr.name == @ifname }&.ifindex
      end

      # @rbs () -> String
      def mr_type
        @mr_type ||= [PACKET_MR_PROMISC].pack('S')
      end

      # @rbs () -> String
      def mr_alen
        @mr_alen ||= [0].pack('S')
      end

      # @rbs () -> String
      def mr_address
        @mr_address ||= [0].pack('C') * 8
      end
    end
  end
end
