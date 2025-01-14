# frozen_string_literal: true

module Redhound
  class Analyzer
    def self.analyze(msg:)
      new(msg: msg).analyze
    end

    def initialize(msg:)
      @msg = msg
    end

    def analyze
      puts 'Analyzing...'
      ether = Header::Ether.generate(bytes: @msg.bytes[0..13])
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
      puts
    end
  end
end
