module Redhound
  class Analyzer
    def self.analyze(msg:)
      new(msg: msg).analyze
    end

    def initialize(msg:)
      @msg = msg
    end

    def analyze
      puts "Analyzing..."
      ether = Header::Ether.generate(bytes: @msg.bytes[0..13])
      pp ether
      ether.dump
      if ether.ipv4?
        ip = Header::Ipv4.generate(bytes: @msg.bytes[14..33])
        ip.dump
        if ip.udp?
          udp = Header::Udp.generate(bytes: @msg.bytes[34..41])
          udp.dump
        elsif ip.icmp?
          icmp = Header::Icmp.generate(bytes: @msg.bytes[34..41])
          icmp.dump
        end
      end
    end
  end
end
