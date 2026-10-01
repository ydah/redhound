# rbs_inline: enabled
# frozen_string_literal: true

require 'socket'

module Redhound
  # @api private
  module Capture
    # @api private
    class Interface
      attr_reader :name, :index, :linktype, :snaplen, :flags, :mtu, :mac, :description, :filter, :meta

      # @rbs (name: String, ?index: Integer, ?linktype: Integer, ?snaplen: Integer, ?flags: Integer, ?mtu: Integer?, ?mac: String?, ?description: String?, ?filter: String?, ?meta: Hash[Symbol, untyped]) -> void
      def initialize(name:, index: 0, linktype: 1, snaplen: 262_144, flags: 0, mtu: nil, mac: nil,
                     description: nil, filter: nil, meta: {})
        @name, @index, @linktype, @snaplen, @flags = name, index, linktype, snaplen, flags
        @mtu, @mac, @description, @filter, @meta = mtu, mac, description, filter, meta
      end

      # @rbs () -> Integer
      def ifindex = @index

      # @rbs () -> bool
      def up? = (@flags & 1).positive?

      # @rbs () -> bool
      def loopback? = (@flags & 8).positive?

      # @rbs () -> bool
      def running? = (@flags & 0x40).positive?

      # @rbs () -> String
      def to_s
        state = [up? ? 'Up' : 'Down', running? ? 'Running' : nil, loopback? ? 'Loopback' : nil].compact.join(', ')
        "#{@index}.#{@name} [#{state}]#{@mac ? " #{@mac}" : ''}#{@mtu ? " mtu #{@mtu}" : ''}"
      end

      # @rbs () -> Array[Interface]
      def self.all
        Socket.getifaddrs.uniq(&:name).map do |address|
          index = address.ifindex || 0
          interface = new(name: address.name, index:, flags: address.flags)
          if RUBY_PLATFORM.include?('linux')
            Linux::Ifreq.interface(address.name, index:)
          else
            interface
          end
        end.sort_by(&:index)
      end

      # @rbs (String | Integer value) -> Interface
      def self.find(value)
        return new(name: 'any', linktype: 276) if value.to_s == 'any'

        found = all.find { |item| item.name == value.to_s || item.index.to_s == value.to_s }
        return found if found

        names = all.map(&:name)
        suggestions = names.select { |name| name.include?(value.to_s[0, 2]) }
        message = "interface #{value.inspect} not found"
        message += "; available: #{(suggestions.empty? ? names : suggestions).join(', ')}"
        raise InterfaceNotFound, message
      end
    end
  end
end
