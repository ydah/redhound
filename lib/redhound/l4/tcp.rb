# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class L4
    # Phase 0 の暫定実装。2.0 では Protocols::Tcp に置き換える
    class Tcp < Base
      FLAG_NAMES = { 0x80 => 'CWR', 0x40 => 'ECE', 0x20 => 'URG', 0x10 => 'ACK',
                     0x08 => 'PSH', 0x04 => 'RST', 0x02 => 'SYN', 0x01 => 'FIN' }.freeze

      # @rbs (bytes: Array[Integer]) -> void
      def initialize(bytes:)
        raise ArgumentError, 'TCP header needs 20 bytes' unless bytes.size >= 20

        @bytes = bytes
      end

      # @rbs () -> Redhound::L4::Tcp
      def generate
        @sport, @dport, @seq, @ack, off_flags, @window, @check, @urgent =
          @bytes[0, 20].pack('C*').unpack('nnNNnnnn')
        @data_offset = (off_flags >> 12) * 4
        raise ArgumentError, "invalid TCP data offset #{@data_offset}" if @data_offset < 20 || @data_offset > @bytes.size

        @flags = off_flags & 0xFF
        @data = @bytes[@data_offset..] || []
        self
      end

      # @rbs () -> String
      def to_s
        <<-TCP
    └─ TCP Src: #{@sport} Dst: #{@dport} Seq: #{@seq} Ack: #{@ack} Flags: [#{flags}] Win: #{@window} Len: #{@data.size}
        └─ Payload: #{Util::SafeText.printable(@data.first(64))}
        TCP
      end

      private

      # @rbs () -> String
      def flags
        FLAG_NAMES.filter_map { |bit, name| name if @flags & bit != 0 }.join(',')
      end
    end
  end
end
