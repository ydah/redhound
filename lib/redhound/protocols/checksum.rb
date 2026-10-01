# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    module Checksum
      # @rbs (String bytes) -> Integer
      def self.value(bytes)
        sum = bytes.unpack('n*').sum
        sum += bytes.getbyte(-1).to_i << 8 if bytes.bytesize.odd?
        sum = (sum & 0xffff) + (sum >> 16) while sum > 0xffff
        (~sum) & 0xffff
      end
      # @rbs (Context ctx, Layer layer, String bytes, ?Integer? proto) -> void
      def self.verify(ctx, layer, bytes, proto = nil)
        return unless ctx.verify_checksums?
        network = ctx.network
        if ctx.packet.direction == :out || ctx.packet.meta[:csum_not_ready] || ctx.embedded || network&.[](:mf) == 1
          layer.diagnose(:note, :checksum_unverified, 'checksum not verified (offloaded or incomplete)')
          return
        end
        if proto && network
          src, dst = network[:src], network[:dst]
          pseudo = if network.protocol == :ipv4
                     [src, dst, 0, proto, bytes.bytesize].pack('NNCCn')
                   else
                     src + dst + [bytes.bytesize, proto].pack('Nx3C')
                   end
          bytes = pseudo + bytes
        end
        layer.diagnose(:warn, :bad_checksum, 'checksum does not match') unless value(bytes).zero?
      end
    end
  end
end
