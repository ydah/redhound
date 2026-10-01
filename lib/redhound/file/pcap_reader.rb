# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module File
    # @api private
    class PcapReader
      attr_reader :interfaces, :linktype

      # @rbs (untyped io, String magic) -> void
      def initialize(io, magic)
        @io = io
        endian, @multiplier = Format::PCAP_MAGICS.fetch(magic) #: [Symbol, Integer]
        @integer_format = endian == :little ? 'V' : 'N'
        header = Format.read_exact(io, 20)
        major, minor, _zone, _accuracy, @snaplen, network = header.unpack(endian == :little ? 'vvV4' : 'nnN4') #: [Integer, Integer, Integer, Integer, Integer, Integer]
        raise FileFormatError, "unsupported pcap version #{major}.#{minor}" unless major == 2 && minor == 4
        raise FileFormatError, 'invalid pcap snaplen' unless @snaplen.between?(1, Format::MAX_RECORD)

        @linktype = network & 0xffff
        @interfaces = [Capture::Interface.new(name: 'pcap', linktype: @linktype, snaplen: @snaplen)]
        @number = 0
      end

      # @rbs () -> Packet?
      def next_packet
        record = Format.read_exact(@io, 16, eof: true)
        return nil unless record

        seconds, fraction, caplen, original_length = record.unpack("#{@integer_format}4") #: [Integer, Integer, Integer, Integer]
        Format.check_lengths(caplen, original_length, @snaplen)
        raise FileFormatError, 'invalid pcap timestamp fraction' unless fraction < 1_000_000_000 / @multiplier

        data = Format.normalize_null(Format.read_exact(@io, caplen), @linktype, @integer_format)
        @number += 1
        timestamp_ns = seconds * 1_000_000_000 + fraction * @multiplier #: Integer
        Packet.new(data, timestamp_ns:,
                         original_length:, linktype: @linktype, interface: @interfaces.first, number: @number)
      end
    end
  end
end
