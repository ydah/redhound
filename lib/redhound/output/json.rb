# rbs_inline: enabled
# frozen_string_literal: true

require 'json'

module Redhound
  # @api private
  module Output
    # @api private
    class Json
      # @rbs (?ndjson: bool) -> void
      def initialize(ndjson: false)
        @ndjson, @started = ndjson, false
      end
      # @rbs (Packet packet, untyped io) -> void
      def format(packet, io)
        if @ndjson
          io.write(JSON.generate(packet.to_h) + "\n")
          return
        end
        io.write(@started ? ",\n" : "[\n")
        io.write(JSON.generate(packet.to_h))
        @started = true
      end
      # @rbs (untyped io) -> void
      def finish(io)
        return if @ndjson
        io.write(@started ? "\n]\n" : "[]\n")
      end
    end
  end
end
