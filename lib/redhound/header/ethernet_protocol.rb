# frozen_string_literal: true

module Redhound
  class Header
    class EthernetProtocol
      ETHERNET_PROTOCOL = {
        0x0060 => 'Loopback',
        0x0800 => 'IPv4',
        0x0806 => 'ARP',
        0x86DD => 'IPv6',
        0x8100 => 'VLAN',
      }

      def initialize(protocol:)
        @protocol = protocol
      end

      def to_s
        ETHERNET_PROTOCOL[@protocol] || 'Unknown'
      end

      ETHERNET_PROTOCOL.each do |id, name|
        method_name = name.downcase.gsub(/[ \-]/, '_') + '?'
        define_method(method_name) do
          @protocol == id
        end
      end
    end
  end
end
