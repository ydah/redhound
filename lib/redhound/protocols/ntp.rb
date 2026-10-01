# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Protocols
    # @api private
    class Ntp < Dissector
      MODES = { 1 => 'symmetric active', 2 => 'symmetric passive', 3 => 'client', 4 => 'server',
                5 => 'broadcast', 6 => 'control', 7 => 'private' }.freeze
      protocol :ntp, name: 'Network Time Protocol', short: 'NTP'
      dissects_on 'udp.port', 123
      header do
        bits 8 do
          bit :li, 'ntp.flags.li', 2
          bit :vn, 'ntp.flags.vn', 3
          bit :mode, 'ntp.flags.mode', 3, enum: MODES
        end
        uint8 :stratum, 'ntp.stratum'
        uint8 :poll, 'ntp.ppoll'
        uint8 :precision, 'ntp.precision'
        uint32 :rootdelay, 'ntp.rootdelay'
        uint32 :rootdispersion, 'ntp.rootdispersion'
        uint32 :refid, 'ntp.refid'
        uint64 :reftime, 'ntp.reftime'
        uint64 :org, 'ntp.org'
        uint64 :rec, 'ntp.rec'
        uint64 :xmt, 'ntp.xmt'
      end

      # @rbs (Context ctx, Layer layer) -> void
      def dissect(ctx, layer)
        layer.values[:poll] -= 256 if layer[:poll] >= 128
        layer.values[:precision] -= 256 if layer[:precision] >= 128
        layer.diagnose(:error, :malformed, 'invalid NTP version or mode') unless layer[:vn].between?(1, 4) && layer[:mode].between?(1, 7)
        if ctx.cursor.remaining > 48
          layer.add(:extension, 'ntp.extension', ctx.cursor.bytes(48, ctx.cursor.remaining - 48),
                    type: :bytes, offset: 48, length: ctx.cursor.remaining - 48)
        end
        layer.payload_offset = layer.payload_end
      end

      # @rbs (Layer layer) -> String
      def summary(layer) = "NTP v#{layer[:vn]} #{MODES[layer[:mode]]}, stratum #{layer[:stratum]}"
    end
  end
end
