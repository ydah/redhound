# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Output
    # @api private
    class Hexdump
      # @rbs (?ascii: bool, ?link_layer: bool) -> void
      def initialize(ascii: false, link_layer: false)
        @ascii, @link_layer = ascii, link_layer
      end
      # @rbs (Packet packet, untyped io) -> void
      def format(packet, io)
        offset = @link_layer ? 0 : (packet.layers.find { |l| %i[ipv4 ipv6 arp].include?(l.protocol) }&.offset || 0)
        data = packet.data.byteslice(offset..) || ''.b
        pos = 0
        while pos < data.bytesize
          chunk = data.byteslice(pos, 16) #: String
          hex = chunk.unpack('H2' * chunk.bytesize).join(' ')
          line = Kernel.format('  0x%04x:  %-47s', pos, hex)
          line += '  ' + chunk.gsub(/[^\x20-\x7e]/n, '.') if @ascii
          io.write(line.rstrip + "\n")
          pos += 16
        end
      end
    end
  end
end
