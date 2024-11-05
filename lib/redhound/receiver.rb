require "socket"

module Redhound
  class Receiver
    class << self
      def run(ifname:)
        new(ifname:).run
      end
    end

    def initialize(ifname:)
      @ifname = ifname
      @socket = SocketBuilder.build(ifname:)
    end

    def run
      loop do
        msg, _ = @socket.recvfrom(2048)
        Analyzer.analyze(msg:)
      end
    end
  end
end
