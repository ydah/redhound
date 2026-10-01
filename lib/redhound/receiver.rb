# rbs_inline: enabled
# frozen_string_literal: true

require 'socket'

module Redhound
  class Receiver
    class << self
      # @rbs (ifname: String, filename: String) -> void
      def run(ifname:, filename:)
        new(ifname:, filename:).run
      end
    end

    # @rbs (ifname: String, filename: String) -> void
    def initialize(ifname:, filename:)
      @ifname = ifname
      @source = Resolver.resolve(ifname:)
      if filename
        @writer = Writer.new(filename:)
        @writer.start
      end
      @count = 0
    rescue StandardError, Interrupt
      @source&.close
      raise
    end

    # @rbs () -> void
    def run
      loop do
        msg, time = @source.next_packet
        @writer&.write(msg:, time:) # 解析より先に保存し、解析失敗でパケットを失わない
        Analyzer.analyze(msg:, count: increment)
      rescue Interrupt
        break
      end
    ensure
      begin
        @writer&.stop
      ensure
        @source.close
      end
    end

    private

    # @rbs () -> Integer
    def increment
      @count.tap { @count += 1 }
    end
  end
end
