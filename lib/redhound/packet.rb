# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # Captured immutable bytes, metadata, and lazily decoded protocol layers.
  class Packet
    # Capture bytes and metadata; timestamp_ns and lengths preserve kernel/file values.
    attr_reader :data, :timestamp_ns, :original_length, :linktype, :interface, :direction, :number, :meta
    # Override the dissection engine before accessing layers.
    attr_accessor :engine
    # @rbs (String data, ?timestamp_ns: Integer, ?original_length: Integer?, ?linktype: (Integer | Symbol), ?interface: untyped, ?direction: Symbol?, ?number: Integer, ?meta: Hash[Symbol, untyped]) -> void
    # Copy binary data and preserve capture metadata; reject impossible original lengths.
    def initialize(data, timestamp_ns: 0, original_length: nil, linktype: 1, interface: nil, direction: nil, number: 1, meta: {})
      @data = data.b.freeze
      raise ArgumentError, 'timestamp_ns must be an Integer' unless timestamp_ns.is_a?(Integer)
      raise ArgumentError, 'number must be a positive Integer' unless number.is_a?(Integer) && number.positive?
      raise ArgumentError, 'direction must be in, out or nil' unless direction.nil? || direction == :in || direction == :out
      @timestamp_ns, @original_length = timestamp_ns, original_length.nil? ? data.bytesize : original_length
      raise ArgumentError, 'original length must be an Integer' unless @original_length.is_a?(Integer)
      raise ArgumentError, 'original length is shorter than captured length' if @original_length < data.bytesize
      @linktype = Capture::Linktype.resolve(linktype)
      @interface, @direction, @number, @meta = interface, direction, number, meta.dup
      @engine = nil # @rbs Engine?
    end
    # @rbs () -> Integer
    # Number of captured bytes.
    def caplen = @data.bytesize
    # @rbs () -> bool
    # Whether capture omitted bytes from the original packet.
    def truncated? = caplen < @original_length
    # @rbs () -> Time
    # Capture timestamp as a nanosecond-precision Time.
    def time = Time.at(@timestamp_ns / 1_000_000_000, @timestamp_ns % 1_000_000_000, :nsec)
    # @rbs () -> Array[Layer]
    # Decode the protocol chain once and return its Layers.
    def layers = (@layers ||= (@engine || Engine.default).dissect(self))
    # @rbs ((Symbol | String) key) -> untyped
    # Select the first layer by symbol or decoded field by dotted name.
    def [](key)
      return layers.find { |l| l.protocol == key } if key.is_a?(Symbol)
      layers.each do |l|
        val = l.field_value(key)
        return val unless val.nil?
      end
      nil
    end
    # @rbs (Symbol protocol) -> Array[Layer]
    # Decode the protocol chain once and return its Layers.
    def layers_of(protocol) = layers.select { |l| l.protocol == protocol }
    # @rbs (Symbol protocol) -> Layer?
    # Return the last matching layer in the protocol chain.
    def innermost(protocol) = layers_of(protocol).last
    # @rbs (String name) -> Array[untyped]
    # Return every decoded value of a repeated field.
    def field_values(name) = layers.flat_map { |l| l.field_values(name) }
    # @rbs () -> String
    # Format a numeric one-line packet summary.
    def summary = Output::Summary.new.line(self)
    # @rbs () -> Hash[Symbol, untyped]
    # Return a JSON-compatible packet matching docs/json-schema.json.
    def to_h
      { frame: { number: @number, time_epoch_ns: @timestamp_ns, time: time.utc.strftime('%Y-%m-%dT%H:%M:%S.') + format('%09dZ', time.nsec),
                 caplen: caplen, len: @original_length, interface: json_text(@interface&.name), direction: @direction, linktype: @linktype },
        layers: layers.map(&:to_h), diagnostics: layers.flat_map { |l| l.diagnostics.map { |d| { layer: l.protocol, severity: d.severity, code: d.code, message: json_text(d.message), field: json_text(d.field) } } } }
    end

    private

    # @rbs (String? text) -> String?
    def json_text(text)
      return nil unless text
      utf8 = text.dup.force_encoding(Encoding::UTF_8)
      return utf8 if utf8.valid_encoding?
      text.unpack1('H*') #: String
    end
  end
end
