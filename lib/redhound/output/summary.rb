# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Output
    # @api private
    class Summary
      # @rbs (?timestamp: Symbol, ?precision: Symbol, ?link_layer: bool, ?quick: bool, ?verbosity: Integer, ?resolve_names: bool) -> void
      def initialize(timestamp: :clock, precision: :micro, link_layer: false, quick: false, verbosity: 0, resolve_names: false)
        @timestamp = Timestamp.new(style: timestamp, precision: precision)
        @link_layer, @quick, @verbosity, @resolve_names = link_layer, quick, verbosity, resolve_names
        @names = {} #: Hash[String, String]
      end
      # @rbs (Packet packet) -> String
      def line(packet)
        parts = [@timestamp.format(packet)]
        if packet.interface
          parts << [packet.interface.name, packet.direction&.to_s&.capitalize].compact.join(' ')
        end
        if @link_layer && (eth = packet[:eth])
          parts << "#{eth.display(:src)} > #{eth.display(:dst)}, ethertype #{eth.display(:type)}, length #{packet.original_length}:"
        end
        network = nil #: Layer?
        transport = nil #: Layer?
        layer = nil #: Layer?
        packet.layers.each do |current|
          next if current.embedded
          case current.protocol
          when :ipv4, :ipv6
            network, transport, layer = current, nil, nil
          when :tcp, :udp
            transport = layer = current
          when :data, :raw, :eth, :vlan, :ipv6_ext, :sll, :sll2, :null
          else layer = current
          end
        end
        if network
          src, dst = address(network.display(:src)), address(network.display(:dst))
          src += ".#{transport[:srcport]}" if transport
          dst += ".#{transport[:dstport]}" if transport
          parts << "#{network.protocol == :ipv4 ? 'IP' : 'IP6'} #{src} > #{dst}:"
        end
        layer ||= packet.layers.last
        klass = layer && Registry.default.protocols[layer.protocol]
        parts << if @quick && transport
                   "#{transport.protocol.to_s.upcase}, length #{[transport.payload_end - transport.payload_offset, 0].max}"
                 elsif klass && layer && !layer.error?
                   klass.new.summary(layer)
                 else
                   "#{layer&.protocol.to_s.upcase}, length #{packet.caplen}"
                 end
        if @verbosity.positive? && network
          parts << "ttl #{network[:ttl] || network[:hlim]}"
          parts << "id #{network.display(:id)}, length #{network[:len]}" if network.protocol == :ipv4
          parts << "checksum #{network.display(:checksum)}" if network[:checksum]
          if transport
            parts << "#{transport.protocol} checksum #{transport.display(:checksum)}"
            options = transport.fields.select { |field| field.name.start_with?('tcp.options.') }
            unless options.empty?
              parts << 'options [' + options.map { |field| "#{field.name.delete_prefix('tcp.options.')} #{field.display}" }.join(', ') + ']'
            end
          end
        end
        diagnostics = packet.layers.flat_map(&:diagnostics)
        parts << diagnostics.map { |d| "[#{d.code}]" }.join(' ') unless diagnostics.empty?
        # All protocol summaries and interface names pass this terminal boundary.
        parts.reject(&:empty?).join(' ').b.gsub(/[^\x20-\x7e]/n) { |c| Kernel.format('\\x%02x', c.getbyte(0)) }
      end
      # @rbs (Packet packet, untyped io) -> void
      def format(packet, io) = io.write(line(packet) + "\n")
      # @rbs (String ip) -> String
      def address(ip)
        return ip unless @resolve_names
        return @names[ip] if @names.key?(ip)
        @names.shift if @names.length >= 256
        @names[ip] = Addrinfo.ip(ip).getnameinfo.first
      rescue SocketError
        ip
      end
    end
  end
end
