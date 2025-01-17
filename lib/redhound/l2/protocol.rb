# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L2
    class Protocol
      PROTO_TABLE = {
        0x0060 => 'Loopback',
        0x0800 => 'IPv4',
        0x0806 => 'ARP',
        0x86DD => 'IPv6',
        0x8100 => 'VLAN',
      }

      # @rbs (protocol: Integer) -> void
      def initialize(protocol:)
        @protocol = protocol
      end

      # @rbs () -> String
      def to_s
        PROTO_TABLE[@protocol] || 'Unknown'
      end

      PROTO_TABLE.each do |id, name|
        method_name = name.downcase.gsub(/[ \-]/, '_') + '?'
        define_method(method_name) do
          @protocol == id
        end
      end
    end
  end
end
