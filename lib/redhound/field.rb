# rbs_inline: enabled
# frozen_string_literal: true

require 'ipaddr'

module Redhound
  # Immutable description of a field location, type and display metadata.
  FieldDefinition = Data.define(:key, :name, :type, :offset, :length, :index, :shift, :mask, :scale, :format, :enum)

  # A decoded field with its definition, raw value and absolute location.
  class Field
    # Definition, raw decoded value and capture location.
    attr_reader :definition, :raw_value, :offset, :length

    # @rbs (untyped definition, untyped value, Integer base) -> void
    # Bind a field definition to its value and layer base offset.
    def initialize(definition, value, base)
      @definition, @raw_value = definition, value
      @offset, @length = base + definition.offset, definition.length
    end

    # @rbs () -> String
    # Stable dotted field name.
    def name = @definition.name
    # @rbs () -> Symbol
    # Declared field representation.
    def type = @definition.type

    # @rbs () -> untyped
    # Decoded value; addresses are returned in human-readable text.
    def value
      case type
      when :ipv4 then [@raw_value].pack('N').unpack('C4').join('.')
      when :ipv6 then IPAddr.new_ntoh(@raw_value).to_s
      when :mac then @raw_value.unpack('H2' * 6).join(':')
      else @raw_value
      end
    end

    # @rbs () -> untyped
    # JSON-safe value; opaque bytes and invalid text are encoded in hexadecimal.
    def json_value
      return @raw_value.unpack1('H*') if type == :bytes
      val = value
      return val unless val.is_a?(String)
      utf8 = val.dup.force_encoding(Encoding::UTF_8)
      utf8.valid_encoding? ? utf8 : val.unpack1('H*')
    end

    # @rbs () -> String
    # Terminal-safe field text with escaped control and non-ASCII bytes.
    def display
      val = value
      return val if type == :ipv4 || type == :ipv6 || type == :mac
      return "#{@definition.enum[val]} (#{val})" if @definition.enum&.key?(val)
      return format('0x%x', val) if @definition.format == :hex
      return @raw_value.unpack1('H*') if type == :bytes
      return val.b.gsub(/[^\x20-\x7e]/n) { |c| format('\\x%02x', c.getbyte(0)) } if val.is_a?(String)
      val.to_s
    end
  end
end
