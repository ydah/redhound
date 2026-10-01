# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # Protocol dispatch and per-session decode-as rules.
  class Registry
    # @rbs () -> Registry
    # Shared registry populated by built-in and custom dissectors.
    def self.default = (@default ||= new)
    # Registered protocol identities and dispatch tables.
    attr_reader :protocols
    # @rbs () -> void
    # Create empty protocol dispatch tables.
    def initialize
      @tables, @protocols, @decode_as = {}, {}, {}
    end
    # @rbs (String key, Integer value, untyped klass) -> void
    # Register a class under a dispatch key and value.
    def register(key, value, klass) = (@tables[key] ||= Hash.new)[value] = klass
    # @rbs (untyped klass) -> void
    # Register a protocol class by its declared identity.
    def register_protocol(klass) = @protocols[klass.protocol_id] = klass
    # @rbs (String key, Integer value) -> untyped
    # Look up a protocol class for a dispatch key and value.
    def lookup(key, value) = (@tables[key] || {})[value]
    # @rbs (String key, Integer src, Integer dst) -> untyped
    # Resolve decode-as rules before registered low/high port dispatch.
    def by_port(key, src, dst)
      ports = [src, dst].sort
      ports.each { |p| return @decode_as[[key, p]] if @decode_as.key?([key, p]) }
      ports.each { |p| return lookup(key, p) if lookup(key, p) }
      nil
    end
    # @rbs (Symbol parent, Context ctx, Cursor cursor) -> untyped
    # Run registered transport heuristics on the bounded payload.
    def heuristic(parent, ctx, cursor)
      return nil unless parent == :tcp || parent == :udp
      (@tables["#{parent}.port"] || {}).each_value do |klass|
        next unless klass.respond_to?(:heuristic?)
        return klass if klass.heuristic?(ctx, cursor)
      end
      nil
    end
    # @rbs (String rule) -> void
    # Apply a transport-port override such as udp.port==8443,dns.
    def decode_as(rule)
      match = /\A(tcp\.port|udp\.port)==(\d+),([a-z0-9_]+)\z/.match(rule)
      raise ConfigurationError, "invalid decode-as rule: #{rule}" unless match
      klass = @protocols[match[3].to_sym]
      port = Integer(match[2])
      raise ConfigurationError, "invalid decode-as protocol or port: #{rule}" unless klass && port.between?(0, 65_535)
      @decode_as[[match[1], port]] = klass
    end
    # @rbs () -> Registry
    # Copy tables and overrides for an independent analysis session.
    def copy
      other = dup
      other.instance_variable_set(:@decode_as, @decode_as.dup)
      other.instance_variable_set(:@tables, @tables.transform_values(&:dup))
      other.instance_variable_set(:@protocols, @protocols.dup)
      other
    end
  end
end
