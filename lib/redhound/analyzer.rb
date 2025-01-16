# frozen_string_literal: true

module Redhound
  class Analyzer
    def self.analyze(msg:, count:)
      new(msg:, count:).analyze
    end

    def initialize(msg:, count:)
      @msg = msg
      @count = count
    end

    def analyze
      l2 = Header::Ether.generate(bytes: @msg.bytes[0..], count: @count)
      l2.dump
      return unless l2.supported_type?

      l3 = layer3_header(l2, l2.size)
      l3.dump
      unless l3.supported_protocol?
        puts "    └─ Unsupported protocol #{l3.protocol}"
        return
      end

      layer4_header(l3, l2.size + l3.size).dump
    end

    def layer3_header(l2, offset)
      if l2.type.ipv4?
        Header::Ipv4.generate(bytes: @msg.bytes[offset..])
      elsif l2.type.ipv6?
        Header::Ipv6.generate(bytes: @msg.bytes[offset..])
      end
    end

    def layer4_header(l3, offset)
      if l3.protocol.udp?
        Header::Udp.generate(bytes: @msg.bytes[offset..])
      elsif l3.protocol.icmp?
        Header::Icmp.generate(bytes: @msg.bytes[offset..])
      end
    end
  end
end
