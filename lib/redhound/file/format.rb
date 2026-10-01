# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module File
    # @api private
    module Format
      MAX_RECORD = 16 * 1024 * 1024
      PCAP_MAGICS = {
        "\xd4\xc3\xb2\xa1".b => [:little, 1_000], "\xa1\xb2\xc3\xd4".b => [:big, 1_000],
        "\x4d\x3c\xb2\xa1".b => [:little, 1], "\xa1\xb2\x3c\x4d".b => [:big, 1]
      }.freeze
      PCAPNG_MAGIC = "\x0a\x0d\x0d\x0a".b.freeze

      # @rbs (untyped io, Integer length, ?eof: false) -> String
      # @rbs (untyped io, Integer length, eof: true) -> String?
      def self.read_exact(io, length, eof: false)
        raise FileFormatError, "invalid record length #{length}" unless length.between?(0, MAX_RECORD)
        return ''.b if length.zero?

        result = ''.b
        while result.bytesize < length
          part = io.read(length - result.bytesize)
          if !part || part.empty?
            return nil if eof && result.empty?

            raise FileFormatError, "truncated capture file (wanted #{length}, read #{result.bytesize})"
          end
          result << part
        end
        result
      end

      # @rbs (Integer length) -> Integer
      def self.padded(length) = (length + 3) & ~3

      # @rbs (String data) -> String
      def self.pad(data) = data + "\0" * (padded(data.bytesize) - data.bytesize)

      # NULL carries a host-order address family; libpcap also normalizes it on read.
      # @rbs (String data, Integer linktype, String integer_format) -> String
      def self.normalize_null(data, linktype, integer_format)
        data[0, 4] = [data.unpack1(integer_format)].pack('L') if linktype.zero? && data.bytesize >= 4
        data
      end

      # @rbs (Integer caplen, Integer original_length, Integer snaplen) -> void
      def self.check_lengths(caplen, original_length, snaplen)
        unless caplen.between?(0, MAX_RECORD) && (snaplen.zero? || caplen <= snaplen) && original_length >= caplen
          raise FileFormatError, "invalid packet lengths (captured #{caplen}, original #{original_length}, snaplen #{snaplen})"
        end
      end
    end
  end
end
