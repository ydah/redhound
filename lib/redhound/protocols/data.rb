# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Data < Dissector
      LENGTH_FIELD = FieldDefinition.new(:length, 'data.len', :uint, 0, 0, 0, nil, nil, 1, nil, nil)
      protocol :data, name: 'Data', short: 'DATA'
      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        length = ctx.cursor.remaining
        layer.definitions << LENGTH_FIELD
        layer.values[:length] = length
        layer.add(:data, 'data.data', ctx.cursor.bytes(0, length), type: :bytes, length: length)
        layer.payload_offset = layer.payload_end
      end
      # @rbs (Layer layer) -> String
      def summary(layer) = "DATA, length #{layer[:length]}"
    end
  end
end
