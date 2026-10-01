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
      bytes = @msg.bytes # 1 パケットにつき 1 回だけ配列化する
      l2 = L2::Ether.generate(bytes:, count: @count)
      l2.dump
      return unless l2.supported_type?

      l3 = L3::Resolver.resolve(bytes: bytes[l2.size..] || [], l2:)
      return unless l3

      l3.dump
      return if l3.is_a?(L3::Arp)

      unless l3.supported_protocol?
        puts "    └─ Unsupported protocol #{l3.protocol}"
        return
      end

      # IP の全長で切り出し、イーサネットのパディングを L4 に渡さない
      l4_bytes = bytes[(l2.size + l3.size)...(l2.size + l3.datagram_length)] || []
      L4::Resolver.resolve(bytes: l4_bytes, l3:)&.dump
    rescue ArgumentError => e
      puts "    └─ [Malformed packet: #{e.message}]"
    end
  end
end
