# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Linux
      # @api private
      module Constants
        AF_PACKET = 17
        SOL_PACKET = 263
        ETH_P_ALL = 3
        PACKET_ADD_MEMBERSHIP = 1
        PACKET_RX_RING = 5
        PACKET_STATISTICS = 6
        PACKET_VERSION = 10
        PACKET_IGNORE_OUTGOING = 23
        PACKET_MR_PROMISC = 1
        PACKET_OUTGOING = 4
        SO_ATTACH_FILTER = 26
        SO_RCVBUFFORCE = 33
        TPACKET_V3 = 2
        SIOCGSTAMPNS = 0x8907
        SIOCGIFHWADDR = 0x8927
        SIOCGIFMTU = 0x8921
        SIOCGIFFLAGS = 0x8913
        TP_STATUS_USER = 0x01
        TP_STATUS_CSUMNOTREADY = 0x08
        TP_STATUS_VLAN_VALID = 0x10
        TP_STATUS_VLAN_TPID_VALID = 0x40
        TP_STATUS_CSUM_VALID = 0x80
        RECEIVE_SIZE = 262_144
      end
    end
  end
end
