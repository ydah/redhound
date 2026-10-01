# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module File
    # @api private
    class PcapngReader
      attr_reader :interfaces, :stats

      # @rbs (untyped io, String magic) -> void
      def initialize(io, magic)
        @io = io
        @interfaces = [] #: Array[Capture::Interface]
        @section_interfaces = [] #: Array[Capture::Interface]
        @statistics = {} #: Hash[Integer, Hash[Symbol, Integer]]
        @packet_counts = {} #: Hash[Integer, Integer]
        @stats = Capture::Stats.new
        @number = 0
        @magic = magic
        @integer_format = 'V'
        read_block
        while (block = read_block)
          type, body = block
          if type == 1
            read_interface(body)
            break
          end
          raise FileFormatError, 'pcapng packet precedes interface description' if [3, 5, 6].include?(type)
        end
      end

      # @rbs () -> Integer
      def linktype = @interfaces.first&.linktype || 1

      # @rbs () -> bool
      def statistics? = !@statistics.empty?

      # @rbs () -> Packet?
      def next_packet
        while (block = read_block)
          type, body = block
          case type
          when 1 then read_interface(body)
          when 6 then return read_enhanced(body)
          when 3 then return read_simple(body)
          when 5 then read_statistics(body)
          end
        end
        nil
      end

      private

      # @rbs () -> [Integer, String]?
      def read_block
        header = @magic ? @magic + Format.read_exact(@io, 4) : Format.read_exact(@io, 8, eof: true)
        @magic = nil
        return nil unless header

        section = header.byteslice(0, 4) == Format::PCAPNG_MAGIC
        prefix = section ? Format.read_exact(@io, 4) : ''.b
        if section
          @integer_format = case prefix
                            when "\x4d\x3c\x2b\x1a".b then 'V'
                            when "\x1a\x2b\x3c\x4d".b then 'N'
                            else raise FileFormatError, 'invalid pcapng byte order magic'
                            end
        end
        type, length = header.unpack("#{@integer_format}2") #: [Integer, Integer]
        minimum = section ? 28 : 12
        unless length.between?(minimum, Format::MAX_RECORD) && (length & 3).zero?
          raise FileFormatError, "invalid pcapng block length #{length}"
        end
        contents = prefix + Format.read_exact(@io, length - 8 - prefix.bytesize)
        raise FileFormatError, 'pcapng block lengths do not match' unless contents.unpack1(@integer_format, offset: contents.bytesize - 4) == length

        body = contents.byteslice(0, contents.bytesize - 4) #: String
        if section
          version = body.unpack(@integer_format == 'V' ? 'vv' : 'nn', offset: 4)
          raise FileFormatError, 'unsupported pcapng section version' unless version == [1, 0]

          @section_interfaces = [] #: Array[Capture::Interface]
        end
        [type, body]
      end

      # @rbs (String body) -> void
      def read_interface(body)
        require_size(body, 8)
        linktype, _reserved, snaplen = body.unpack(@integer_format == 'V' ? 'vvV' : 'nnN') #: [Integer, Integer, Integer]
        raise FileFormatError, 'invalid pcapng snaplen' if snaplen > Format::MAX_RECORD

        opts = options(body, 8)
        resolution = opts.fetch(9, ["\x06".b]).fetch(0)
        raise FileFormatError, 'invalid pcapng timestamp resolution' unless resolution.bytesize == 1

        exponent = resolution.getbyte(0) #: Integer
        units = exponent < 128 ? 10**exponent : 2**(exponent & 127)
        offset = opts.fetch(14, ["\0" * 8]).fetch(0)
        raise FileFormatError, 'invalid pcapng timestamp offset' unless offset.bytesize == 8

        index = @section_interfaces.size
        filter_option = opts[11]&.first
        interface = Capture::Interface.new(name: opts.fetch(2, ["interface#{index}"]).fetch(0), index:, linktype:, snaplen:,
                                           description: opts[3]&.first, filter: filter_option && filter_option.getbyte(0) == 0 ? filter_option.byteslice(1..) : nil,
                                           meta: { timestamp_units: units, timestamp_offset: offset.unpack1(@integer_format == 'V' ? 'q<' : 'q>') })
        @section_interfaces << interface
        @interfaces << interface
      end

      # @rbs (String body) -> Packet
      def read_enhanced(body)
        require_size(body, 20)
        index, high, low, caplen, original_length = body.unpack("#{@integer_format}5") #: [Integer, Integer, Integer, Integer, Integer]
        interface = interface_at(index)
        Format.check_lengths(caplen, original_length, interface.snaplen)
        require_size(body, 20 + Format.padded(caplen))
        opts = options(body, 20 + Format.padded(caplen))
        flags_option = opts[2]&.first
        raise FileFormatError, 'invalid pcapng packet flags' if flags_option && flags_option.bytesize != 4

        flags = flags_option ? flags_option.unpack1(@integer_format) : 0 #: Integer
        direction = { 1 => :in, 2 => :out }[flags & 3]
        meta = { epb_flags: flags } #: Hash[Symbol, untyped]
        meta[:comment] = opts[1].join("\n") if opts[1]
        pkttype = direction == :out ? 4 : { 1 => 0, 2 => 2, 3 => 1, 4 => 3 }[(flags >> 2) & 7]
        meta[:pkttype] = pkttype if pkttype
        timestamp_ns = ((high << 32) | low) * 1_000_000_000 / interface.meta.fetch(:timestamp_units) +
                       interface.meta.fetch(:timestamp_offset) * 1_000_000_000
        data = body.byteslice(20, caplen) #: String
        make_packet(data, interface, original_length, timestamp_ns, direction, meta)
      end

      # @rbs (String body) -> Packet
      def read_simple(body)
        require_size(body, 4)
        interface = interface_at(0)
        original_length = body.unpack1(@integer_format) #: Integer
        caplen = interface.snaplen.zero? ? original_length : [original_length, interface.snaplen].min
        Format.check_lengths(caplen, original_length, interface.snaplen)
        raise FileFormatError, 'invalid pcapng simple packet length' unless body.bytesize == 4 + Format.padded(caplen)

        data = body.byteslice(4, caplen) #: String
        make_packet(data, interface, original_length, 0, nil, {})
      end

      # @rbs (String body) -> void
      def read_statistics(body)
        require_size(body, 12)
        index = body.unpack1(@integer_format) #: Integer
        interface = interface_at(index)
        opts = options(body, 12)
        values = {} #: Hash[Symbol, Integer]
        { received: 4, dropped: 5, if_dropped: 7, captured: 8 }.each do |name, code|
          option = opts[code]&.first
          next unless option
          raise FileFormatError, 'invalid pcapng statistics counter' unless option.bytesize == 8

          count = option.unpack1(@integer_format == 'V' ? 'Q<' : 'Q>') #: Integer
          values[name] = count
        end
        @statistics[interface.object_id] = values
        totals = %i[received dropped if_dropped captured].to_h { |name| [name, @statistics.values.sum { |entry| entry.fetch(name, 0) }] }
        %i[received captured].each do |name|
          totals[name] = @packet_counts.values.sum unless @statistics.values.any? { |entry| entry.key?(name) }
        end
        @stats = Capture::Stats.new(**totals)
      end

      # @rbs (String data, Capture::Interface interface, Integer original_length, Integer timestamp_ns, Symbol? direction, Hash[Symbol, untyped] meta) -> Packet
      def make_packet(data, interface, original_length, timestamp_ns, direction, meta)
        data = Format.normalize_null(data, interface.linktype, @integer_format)
        @number += 1
        @packet_counts[interface.object_id] = @packet_counts.fetch(interface.object_id, 0) + 1
        Packet.new(data, timestamp_ns:, original_length:, linktype: interface.linktype, interface:, direction:, number: @number, meta:)
      end

      # @rbs (Integer index) -> Capture::Interface
      def interface_at(index)
        @section_interfaces.fetch(index) { raise FileFormatError, "pcapng references unknown interface #{index}" }
      end

      # @rbs (String body, Integer offset) -> Hash[Integer, Array[String]]
      def options(body, offset)
        result = {} #: Hash[Integer, Array[String]]
        while offset < body.bytesize
          require_size(body, offset + 4)
          code, length = body.unpack(@integer_format == 'V' ? 'vv' : 'nn', offset:) #: [Integer, Integer]
          offset += 4
          if code.zero?
            raise FileFormatError, 'invalid pcapng end of options' unless length.zero?
            break
          end
          require_size(body, offset + Format.padded(length))
          value = body.byteslice(offset, length) #: String
          (result[code] ||= []) << value
          offset += Format.padded(length)
        end
        result
      end

      # @rbs (String body, Integer size) -> void
      def require_size(body, size)
        raise FileFormatError, 'truncated pcapng block' if body.bytesize < size
      end
    end
  end
end
