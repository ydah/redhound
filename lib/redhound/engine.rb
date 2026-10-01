# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  class Engine
    MAX_DEPTH = 32
    # @rbs () -> Engine
    def self.default = (@default ||= new)
    # @rbs (?registry: Registry, ?verify_checksums: bool) -> void
    def initialize(registry: Registry.default, verify_checksums: false)
      @registry, @verify_checksums = registry, verify_checksums
    end
    # @rbs (Packet packet) -> Array[Layer]
    def dissect(packet)
      ctx = Context.new(packet, registry: @registry, verify_checksums: @verify_checksums)
      klass = @registry.lookup('linktype', packet.linktype) || Protocols::Data
      loop do
        cursor = ctx.cursor
        layer = safely(klass, ctx, cursor)
        ctx.layers << layer
        break if layer.error? || layer.payload_empty? || klass == Protocols::Data
        if ctx.layers.length >= MAX_DEPTH
          layer.diagnose(:error, :depth_exceeded)
          break
        end
        ctx.cursor = cursor.sub(layer.payload_offset, layer.payload_end)
        next_klass = next_dissector(klass, ctx, layer)
        break if layer.error?
        klass = next_klass || Protocols::Data
      end
      if packet.meta[:possible_truncation]
        ctx.layers.first.diagnose(:warn, :capture_truncated, 'receive buffer limit reached; original packet length is unknown')
      end
      ctx.layers
    end

    # @rbs (untyped klass, Context ctx, Layer layer) -> untyped
    def next_dissector(klass, ctx, layer)
      klass.new.next_dissector(ctx, layer) || @registry.heuristic(layer.protocol, ctx, ctx.cursor)
    rescue Cursor::Truncated => e
      layer.diagnose(:note, :truncated, e.message)
      nil
    rescue StandardError => e
      raise if ENV['REDHOUND_STRICT'] == '1'
      layer.diagnose(:error, :dissector_bug, "#{e.class}: #{e.message}")
      nil
    end

    # @rbs (untyped klass, Context ctx, Cursor cursor) -> Layer
    def safely(klass, ctx, cursor)
      layer = klass.new.parse(ctx, cursor)
      if layer.payload_offset < cursor.start || layer.payload_end < layer.payload_offset
        layer.diagnose(:error, :bad_length)
      elsif layer.payload_offset > cursor.limit || layer.payload_end > cursor.limit
        layer.diagnose(:note, :truncated)
        layer.payload_end = cursor.limit
      end
      layer
    rescue Cursor::Truncated => e
      Layer.new(klass.protocol_id, cursor.start, cursor.remaining, cursor.limit, embedded: ctx.embedded)
           .diagnose(:note, :truncated, e.message)
    rescue StandardError => e
      raise if ENV['REDHOUND_STRICT'] == '1'
      Layer.new(klass.protocol_id, cursor.start, 0, cursor.limit, embedded: ctx.embedded)
           .diagnose(:error, :dissector_bug, "#{e.class}: #{e.message}")
    end
  end
end
