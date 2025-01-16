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
      @source = Resolver.resolve(ifname:)
      if filename
        @writer = Writer.new(filename:)
        @writer.start
      end
      @count = 0
    end

    def run
      loop do
        msg, = @source.next_packet
        Analyzer.analyze(msg:, count: increment)
        @writer&.write(msg)
      rescue Interrupt
        @writer&.stop
        break
      end
    end

    private

    def increment
      @count.tap { @count += 1 }
    end
  end
end
