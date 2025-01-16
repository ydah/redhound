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
      ether = Header::Ether.generate(bytes: @msg.bytes[0..13], count: @count)
      ether.dump
      return unless ether.ipv4?

      ip = Header::Ipv4.generate(bytes: @msg.bytes[14..33])
      ip.dump
      if ip.udp?
        udp = Header::Udp.generate(bytes: @msg.bytes[34..])
        udp.dump
      elsif ip.icmp?
        icmp = Header::Icmp.generate(bytes: @msg.bytes[34..])
        icmp.dump
      end
    end
  end
end
