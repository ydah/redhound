# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  class Context
    attr_reader :packet, :registry, :layers
    attr_accessor :cursor, :embedded, :extension_count
    # @rbs (Packet packet, registry: Registry, ?verify_checksums: bool) -> void
    def initialize(packet, registry:, verify_checksums: false)
      @packet, @registry, @verify_checksums = packet, registry, verify_checksums
      @cursor = Cursor.new(packet.data)
      @embedded, @extension_count, @layers = false, 0, []
    end
    # @rbs () -> bool
    def verify_checksums? = @verify_checksums
    # @rbs () -> Layer?
    def network = @layers.reverse.find { |l| %i[ipv4 ipv6].include?(l.protocol) && l.embedded == @embedded }
  end
end
