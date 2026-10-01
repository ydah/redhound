# rbs_inline: enabled
# frozen_string_literal: true

require 'socket'

module Redhound
  module Builder
    class Socket
      SOL_PACKET            = 263    # linux/socket.h
      PACKET_ADD_MEMBERSHIP = 1      # linux/if_packet.h
      ETH_P_ALL             = 0x0003 # linux/if_ether.h (ホストバイトオーダの値)

      class << self
        # @rbs (ifname: String, ?promiscuous: bool) -> Redhound::Source::Socket
        def build(ifname:, promiscuous: true)
          new(ifname:, promiscuous:).build
        end
      end

      # @rbs (ifname: String, ?promiscuous: bool) -> void
      def initialize(ifname:, promiscuous: true)
        @mq_req = PacketMreq.new(ifname:)
        @promiscuous = promiscuous
      end

      # protocol=0 で作成すると bind するまで 1 パケットも受信しない (packet(7))。
      # 先に全オプションを設定してから bind することで、他 IF のパケット混入を防ぐ。
      # @rbs () -> Redhound::Source::Socket
      def build
        socket = ::Socket.new(::Socket::AF_PACKET, ::Socket::SOCK_RAW, 0)
        socket.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, @mq_req.build) if @promiscuous
        socket.bind([::Socket::AF_PACKET, ETH_P_ALL, @mq_req.ifindex].pack('S n l x12')) # struct sockaddr_ll (20 bytes)
        Redhound::Source::Socket.new(socket:)
      rescue StandardError, Interrupt
        socket&.close
        raise
      end
    end
  end
end
