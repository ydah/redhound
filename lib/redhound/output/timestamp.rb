# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Output
    # @api private
    class Timestamp
      # @rbs (?style: Symbol, ?precision: Symbol) -> void
      def initialize(style: :clock, precision: :micro)
        @style, @precision, @first, @previous = style, precision, nil, nil
      end
      # @rbs (Packet packet) -> String
      def format(packet)
        ns = packet.timestamp_ns
        @first ||= ns
        value = case @style
                when :none then ''
                when :epoch then seconds(ns)
                when :delta then seconds(@previous ? ns - @previous : 0)
                when :elapsed then seconds(ns - @first)
                when :date then packet.time.strftime('%Y-%m-%d %H:%M:%S.') + fraction(ns)
                else packet.time.strftime('%H:%M:%S.') + fraction(ns)
                end
        @previous = ns
        value
      end
      # @rbs (Integer ns) -> String
      def fraction(ns) = Kernel.format(@precision == :nano ? '%09d' : '%06d', @precision == :nano ? ns.abs % 1_000_000_000 : (ns.abs % 1_000_000_000) / 1000)
      # @rbs (Integer ns) -> String
      def seconds(ns) = "#{ns.negative? ? '-' : ''}#{ns.abs / 1_000_000_000}.#{fraction(ns)}"
    end
  end
end
