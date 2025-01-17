# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class Writer
    # @rbs (filename: String) -> void
    def initialize(filename:)
      @filename = filename
    end

    # @rbs () -> void
    def start
      @file = File.open(@filename, 'wb')
      @file.write(file_header)
    end

    # @rbs (msg: String) -> void
    def write(msg:)
      @file.write(packet_record(Time.now, msg.bytesize, msg.bytesize))
      @file.write(msg)
    end

    # @rbs () -> void
    def stop
      @file.close
    end

    private

    # @rbs () -> String
    def file_header
      [
        0xa1b2c3d4, # Magic Number (little-endian)
        2,          # Version Major
        4,          # Version Minor
        0,          # Timezone offset (GMT)
        0,          # Timestamp accuracy
        65535,      # Snapshot length
        1           # Link-layer header type (Ethernet)
      ].pack('VvvVVVV')
    end

    # @rbs (Time timestamp, Integer captured_length, Integer original_length) -> String
    def packet_record(timestamp, captured_length, original_length)
      [
        timestamp.to_i,           # Timestamp seconds
        timestamp.usec || 0,      # Timestamp microseconds
        captured_length,          # Captured packet length
        original_length           # Original packet length
      ].pack('VVVV')
    end
  end
end
