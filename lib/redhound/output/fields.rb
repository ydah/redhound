# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Output
    # @api private
    class Fields
      # @rbs (Array[String] names) -> void
      def initialize(names) = @names = names
      # @rbs (Packet packet, untyped io) -> void
      def format(packet, io)
        cells = @names.map do |name|
          packet.layers.flat_map(&:fields).select { |f| f.name == name }.map(&:display).join(',')
        end
        io.write(cells.join("\t") + "\n")
      end
    end
  end
end
