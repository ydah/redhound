# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # Checked binary reads within an absolute packet slice.
  class Cursor
    # Internal exception for a checked read beyond the captured slice.
    class Truncated < StandardError; end
    # Underlying data and absolute start/end bounds.
    attr_reader :data, :start, :limit

    # @rbs (String data, ?Integer start, ?Integer? limit) -> void
    # Create a bounded view; reject invalid ranges.
    def initialize(data, start = 0, limit = nil)
      @data, @start, @limit = data, start, limit || data.bytesize
      raise ArgumentError, 'invalid cursor bounds' if start.negative? || @limit < start || @limit > data.bytesize
    end

    # @rbs () -> Integer
    # Remaining slice length in bytes.
    def remaining = @limit - @start
    # @rbs (Integer off) -> Integer
    # Read an unsigned byte.
    def u8(off)
      check(off, 1)
      @data.getbyte(@start + off) #: Integer
    end
    # @rbs (Integer off) -> Integer
    # Read an unsigned network-order 16-bit integer.
    def u16(off)
      check(off, 2)
      @data.unpack1('n', offset: @start + off) #: Integer
    end
    # @rbs (Integer off) -> Integer
    # Read an unsigned network-order 32-bit integer.
    def u32(off)
      check(off, 4)
      @data.unpack1('N', offset: @start + off) #: Integer
    end
    # @rbs (Integer off) -> Integer
    # Read an unsigned network-order 64-bit integer.
    def u64(off)
      check(off, 8)
      @data.unpack1('Q>', offset: @start + off) #: Integer
    end
    # @rbs (String template, Integer size, ?Integer off) -> Array[untyped]
    # Unpack a checked fixed-width header.
    def unpack(template, size, off = 0) = (check(off, size); @data.unpack(template, offset: @start + off))
    # @rbs (Integer off, Integer len) -> String
    # Read a checked binary substring.
    def bytes(off, len)
      check(off, len)
      @data.byteslice(@start + off, len) #: String
    end

    # @rbs (Integer from, Integer to) -> Cursor
    # Create a child slice that cannot escape the parent bounds.
    def sub(from, to)
      raise ArgumentError, 'child cursor escapes parent' if from < @start || from > @limit || to < from
      Cursor.new(@data, from, [to, @limit].min)
    end

    # @rbs (Integer off, Integer len) -> void
    # Validate a relative offset and read length.
    def check(off, len)
      raise Truncated, "need #{len} bytes at #{@start + off}, limit #{@limit}" if off.negative? || len.negative? || off + len > remaining
    end
  end
end
