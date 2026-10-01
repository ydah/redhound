# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Analysis
    # @api private
    module FlowKey
      # @rbs (Packet packet, ?Symbol? type) -> untyped
      def self.from(packet, type = nil)
        layers = packet.layers.reject(&:embedded)
        if type == :eth
          layer = layers.find { |item| item.protocol == :eth }
          return nil unless layer && layer[:src] && layer[:dst]
          return normalize(:eth, [layer.display(:src), 0], [layer.display(:dst), 0])
        end
        transport = layers.reverse.find { |item| %i[tcp udp icmp icmpv6].include?(item.protocol) }
        if type && %i[tcp udp].include?(type)
          return nil unless transport && transport.protocol == type
        end
        network = if type == :ip || type == :ipv6
                    layers.find { |item| item.protocol == (type == :ip ? :ipv4 : :ipv6) }
                  elsif transport
                    position = layers.index(transport) #: Integer
                    layers.take(position).reverse.find { |item| %i[ipv4 ipv6].include?(item.protocol) }
                  else
                    layers.reverse.find { |item| %i[ipv4 ipv6].include?(item.protocol) }
                  end
        return nil unless network && network[:src] && network[:dst]
        proto = type || transport&.protocol
        unless proto
          position = layers.index(network) #: Integer
          extensions = layers.drop(position + 1).take_while { |item| item.protocol == :ipv6_ext }
          number = network.protocol == :ipv4 ? network[:proto] : extensions.last&.[](:next) || network[:nxt]
          proto = "ip_proto_#{number}".to_sym
        end
        if %i[tcp udp].include?(proto)
          return nil unless transport && transport[:srcport] && transport[:dstport]
          ports = [transport[:srcport], transport[:dstport]]
        elsif %i[icmp icmpv6].include?(proto)
          return nil unless transport
          # Echo request/reply share a type series and identifier in both directions.
          series = { 8 => 0, 128 => 129 }.fetch(transport[:type], transport[:type])
          ports = [[series, transport[:ident] || 0], [series, transport[:ident] || 0]]
        else
          ports = [0, 0]
        end
        normalize(proto, [network.display(:src), ports[0]], [network.display(:dst), ports[1]])
      end

      # @rbs (Symbol proto, untyped src, untyped dst) -> untyped
      def self.normalize(proto, src, dst)
        reverse = (src <=> dst).positive?
        a, b = reverse ? [dst, src] : [src, dst]
        [[proto, *a, *b].freeze, reverse ? 1 : 0]
      end
    end
  end
end
