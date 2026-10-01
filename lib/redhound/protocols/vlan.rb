# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Vlan < Dissector
      protocol :vlan, name: '802.1Q VLAN', short: 'VLAN'
      dissects_on 'ethertype', 0x8100, 0x88a8, 0x9100
      header do
        bits 16 do
          bit :priority, 'vlan.priority', 3
          bit :dei, 'vlan.dei', 1
          bit :id, 'vlan.id', 12
        end
        uint16 :type, 'vlan.etype', format: :hex
      end
      # @rbs (Context ctx, Layer layer) -> untyped
      def next_dissector(ctx, layer) = ctx.registry.lookup('ethertype', layer[:type])
    end
  end
end
