# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class Analyzer
    # @rbs (msg: String, count: Integer) -> void
    def self.analyze(msg:, count:)
      new(msg:, count:).analyze
    end

    # @rbs (msg: String, count: Integer) -> void
    def initialize(msg:, count:)
      @msg = msg
      @count = count
    end

    # @rbs () -> void
    def analyze
      l2 = L2::Ether.generate(bytes: @msg.bytes[0..], count: @count)
      l2.dump
      return unless l2.supported_type?

      l3 = L3::Resolver.resolve(bytes: @msg.bytes[l2.size..], l2:)
      return if !l3 || @msg.bytes.size <= l2.size + l3.size
      l3.dump
      unless l3.supported_protocol?
        puts "    └─ Unsupported protocol #{l3.protocol}"
        return
      end

      L4::Resolver.resolve(bytes: @msg.bytes[(l2.size + l3.size)..], l3:)&.dump
    end
  end
end
