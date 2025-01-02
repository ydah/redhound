# frozen_string_literal: true

require 'socket'

module Redhound
  class Receiver
    class << self
      def run(ifname:, filename:)
        new(ifname:, filename:).run
      end
    end

    def initialize(ifname:, filename:)
      @ifname = ifname
      @socket = SocketBuilder.build(ifname:)
      if filename
        @writer = Writer.new(filename:)
        @writer.start
      end
    end

    def run
      loop do
        msg, = @socket.recvfrom(2048)
        Analyzer.analyze(msg:)
        @writer.write(msg) if @writer
      rescue Interrupt
        @writer.stop if @writer
        break
      end
    end
  end
end
