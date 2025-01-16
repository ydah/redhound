# frozen_string_literal: true

module Redhound
  class Header
    class Ipv6
      class << self
        def generate(bytes:)
          new(bytes:).generate
        end

        attr_reader :protocol

        def initialize(bytes:)
          raise ArgumentError, "bytes must be bigger than #{header_size} bytes" unless bytes.size >= header_size

          @bytes = bytes
        end

        def size = 40

        def generate
          version_traffic_flow = @bytes[0..3].unpack('N')
          @version = (version_traffic_flow >> 28) & 0xF
          @traffic_class = (version_traffic_flow >> 20) & 0xFF
          @flow_label = version_traffic_flow & 0xFFFFF
          @payload_length = @bytes[4..5]
          @next_header = @bytes[6]
          @hop_limit = @bytes[7]
          @saddr = @bytes[8..23]
          @daddr = @bytes[24..39]
          @protocol = InternetProtocol.new(protocol: @next_header)
        end

        def dump
          puts self
        end

        def to_s
          " └─ IPv6 Ver: #{version} Traffic Class: #{traffic_class} Flow Label: #{flow_label} Payload Length: #{payload_length} Next Header: #{@protocol} Hop Limit: #{hop_limit} Src: #{saddr} Dst: #{daddr}"
        end

        def supported_protocol?
          @protocol.udp?
        end

        def payload_length
          @payload_length.map { |b| b.to_s(16).rjust(2, '0') }.join.to_i(16)
        end

        def saddr
          @saddr.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
        end

        def daddr
          @daddr.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
        end
      end
    end
  end
end
