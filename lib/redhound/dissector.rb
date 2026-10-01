# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # Base class and declarative fixed-header DSL for custom protocols.
  class Dissector
    # Unpack formats and byte lengths supported by the header DSL.
    TYPES = { int8: ['c', 1], uint8: ['C', 1], uint16: ['n', 2], uint32: ['N', 4], uint64: ['Q>', 8],
              mac: ['a6', 6], ipv4: ['N', 4], ipv6: ['a16', 16] }.freeze

    # Build a single unpack template and its field descriptions.
    class Header
      # Compiled unpack template, header byte length and field definitions.
      attr_reader :template, :length, :definitions
      # @rbs () -> void
      # Start an empty fixed-header definition.
      def initialize
        @template, @length, @index, @definitions = +'', 0, 0, []
      end

      # @rbs (Symbol type, Symbol key, String name, **untyped opts) -> void
      # Append a typed fixed-width field with optional format/enum metadata.
      def field(type, key, name, **opts)
        fmt, size = TYPES.fetch(type)
        @definitions << FieldDefinition.new(key, name, type, @length, size, @index, nil, nil, 1, opts[:format], opts[:enum])
        @template << fmt
        @length += size
        @index += 1
      end
      # @rbs (Symbol key, String name, **untyped opts) -> void
      # Append a signed 8-bit field.
      def int8(key, name, **opts) = field(:int8, key, name, **opts)
      # @rbs (Symbol key, String name, **untyped opts) -> void
      # Append an unsigned 8-bit field.
      def uint8(key, name, **opts) = field(:uint8, key, name, **opts)
      # @rbs (Symbol key, String name, **untyped opts) -> void
      # Append a network-order unsigned 16-bit field.
      def uint16(key, name, **opts) = field(:uint16, key, name, **opts)
      # @rbs (Symbol key, String name, **untyped opts) -> void
      # Append a network-order unsigned 32-bit field.
      def uint32(key, name, **opts) = field(:uint32, key, name, **opts)
      # @rbs (Symbol key, String name, **untyped opts) -> void
      # Append a network-order unsigned 64-bit field.
      def uint64(key, name, **opts) = field(:uint64, key, name, **opts)
      # @rbs (Symbol key, String name, **untyped opts) -> void
      # Append a six-byte MAC address.
      def mac(key, name, **opts) = field(:mac, key, name, **opts)
      # @rbs (Symbol key, String name, **untyped opts) -> void
      # Append a four-byte IPv4 address.
      def ipv4(key, name, **opts) = field(:ipv4, key, name, **opts)
      # @rbs (Symbol key, String name, **untyped opts) -> void
      # Append a sixteen-byte IPv6 address.
      def ipv6(key, name, **opts) = field(:ipv6, key, name, **opts)

      # @rbs (Integer width) { (Header) [self: Header] -> void } -> void
      # Define bit fields filling an 8/16/32/64-bit network-order word.
      def bits(width, &block)
        raise ArgumentError, 'bit width must be 8, 16, 32 or 64' unless [8, 16, 32, 64].include?(width)
        @bit_width, @bit_left = width, width
        instance_eval(&block)
        raise ArgumentError, 'bit fields must fill the word' unless @bit_left.zero?
        @template << TYPES.fetch("uint#{width}".to_sym).first
        @length += width / 8
        @index += 1
      end

      # @rbs (Symbol key, String name, Integer width, **untyped opts) -> void
      # Append a bit field inside bits, optionally scaled/formatted.
      def bit(key, name, width, **opts)
        raise ArgumentError, 'invalid bit field width' unless width.positive? && width <= @bit_left
        @bit_left -= width
        @definitions << FieldDefinition.new(key, name, :bits, @length, @bit_width / 8, @index,
                                            @bit_left, (1 << width) - 1, opts.fetch(:scale, 1), opts[:format], opts[:enum])
      end
    end

    class << self
      # @rbs () -> Symbol
      # Registered protocol symbol.
      def protocol_id = @protocol_id
      # @rbs () -> String
      # Human-readable protocol name.
      def protocol_name = @protocol_name
      # @rbs () -> String
      # Short output label.
      def short_name = @short_name
      # @rbs () -> untyped
      # Compiled header definition, if one was declared.
      def compiled_header = @compiled_header
      # @rbs (Symbol id, name: String, short: String) -> void
      # Declare protocol identity and register the dissector.
      def protocol(id, name:, short:)
        @protocol_id, @protocol_name, @short_name = id, name, short
        Registry.default.register_protocol(self)
      end
      # @rbs (String key, *Integer values) -> void
      # Register this protocol under one or more dispatch values.
      def dissects_on(key, *values)
        values.each { |value| Registry.default.register(key, value, self) }
      end
      # @rbs () { (Header) [self: Header] -> void } -> void
      # Compile a fixed header from the DSL block.
      def header(&block)
        @compiled_header = Header.new
        @compiled_header.instance_eval(&block)
        @compiled_header.template.freeze
      end
      # @rbs () -> String
      # Compiled unpack template, or an empty template.
      def header_template = @compiled_header&.template || ''
    end

    # @rbs (Context ctx, Cursor cursor) -> Layer
    # Decode fixed fields then invoke the variable-header hook.
    def parse(ctx, cursor)
      header = self.class.compiled_header
      length = header&.length || 0
      truncated = cursor.remaining < length
      raw = if truncated
              cursor.bytes(0, cursor.remaining).unpack(self.class.header_template)
            else
              cursor.unpack(self.class.header_template, length)
            end
      defs = header ? header.definitions.dup : Array.new
      defs.select! { |d| d.offset + d.length <= cursor.remaining } if truncated
      values = {} #: Hash[Symbol, untyped]
      defs.each do |d|
        val = raw[d.index]
        val = ((val >> d.shift) & d.mask) * d.scale if d.shift
        values[d.key] = val
      end
      layer = Layer.new(self.class.protocol_id, cursor.start, truncated ? cursor.remaining : length, cursor.limit,
                        definitions: defs, values: values, embedded: ctx.embedded)
      return layer.diagnose(:note, :truncated, "need #{length} header bytes, have #{cursor.remaining}") if truncated
      begin
        dissect(ctx, layer)
      rescue Cursor::Truncated => e
        layer.diagnose(:note, :truncated, e.message)
      end
      layer
    end
    # @rbs (Context ctx, Layer layer) -> void
    # Override to parse variable fields using the bounded Context cursor.
    def dissect(ctx, layer); end
    # @rbs (Context ctx, Layer layer) -> untyped
    # Override to return the next protocol class or nil.
    def next_dissector(ctx, layer) = nil
    # @rbs (Layer layer) -> String
    # Override to format the layer summary.
    def summary(layer) = self.class.short_name || layer.protocol.to_s.upcase
  end
end
