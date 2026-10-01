# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # One decoded protocol header and its payload bounds, fields and diagnostics.
  class Layer
    # Protocol identity, captured offset, decoded values and diagnostics.
    attr_reader :protocol, :offset, :diagnostics, :definitions, :values, :embedded
    # Header size and absolute payload bounds used by child dissectors.
    attr_accessor :header_length, :payload_offset, :payload_end

    # @rbs (Symbol protocol, Integer offset, Integer length, Integer limit, ?definitions: Array[untyped], ?values: Hash[Symbol, untyped], ?embedded: bool) -> void
    # Create a bounded header with optional fixed field definitions and values.
    def initialize(protocol, offset, length, limit, definitions: [], values: {}, embedded: false)
      @protocol, @offset, @header_length = protocol, offset, length
      @payload_offset, @payload_end = offset + length, limit
      @definitions, @values, @embedded = definitions, values, embedded
      @diagnostics = [] # @rbs Array[untyped]
    end

    # @rbs (Symbol key) -> untyped
    # Read the raw value identified by a symbolic field key.
    def [](key) = @values[key]
    # @rbs () -> Integer
    # Decoded header length in bytes.
    def length = @header_length
    # @rbs () -> bool
    # Whether no bytes remain for a child protocol.
    def payload_empty? = @payload_offset >= @payload_end
    # @rbs () -> bool
    # Whether an error or truncation stops the protocol chain.
    def error? = @diagnostics.any? { |d| d.severity == :error || d.code == :truncated }

    # @rbs (Symbol severity, Symbol code, ?String message, ?String? field) -> Layer
    # Append a structured diagnostic and return this layer.
    def diagnose(severity, code, message = code.to_s, field = nil)
      @diagnostics << Diagnostic.new(severity, code, message, field)
      self
    end

    # @rbs (Symbol key, String name, untyped value, ?type: Symbol, ?offset: Integer, ?length: Integer, ?format: Symbol?, ?enum: untyped) -> Layer
    # Append a dynamic field with its value, representation and location.
    def add(key, name, value, type: :uint, offset: 0, length: 0, format: nil, enum: nil)
      @values[key] = value
      @definitions << FieldDefinition.new(key, name, type, offset, length, 0, nil, nil, 1, format, enum)
      self
    end

    # @rbs () -> Array[Field]
    # Return Field objects for all fixed and dynamic definitions.
    def fields = @definitions.map { |d| Field.new(d, @values[d.key], @offset) }
    # @rbs (Symbol key) -> String
    # Return escaped text for a single symbolic field.
    def display(key)
      definition = @definitions.find { |d| d.key == key }
      definition ? Field.new(definition, @values[key], @offset).display : ''
    end
    # @rbs (String name) -> untyped
    # Read the first decoded value with this dotted field name.
    def field_value(name)
      definition = @definitions.find { |d| d.name == name }
      definition ? Field.new(definition, @values[definition.key], @offset).value : nil
    end
    # @rbs (String name) -> Array[untyped]
    # Read the first decoded value with this dotted field name.
    def field_values(name) = fields.select { |f| f.name == name }.map(&:value)

    # @rbs () -> Hash[Symbol, untyped]
    # Return JSON fields, grouping repeated names into arrays.
    def to_h
      { protocol: @protocol, offset: @offset, length: length, embedded: @embedded,
        fields: fields.group_by(&:name).to_h { |name, group| [name, group.length == 1 ? group.first.json_value : group.map(&:json_value)] } }
    end
  end
end
