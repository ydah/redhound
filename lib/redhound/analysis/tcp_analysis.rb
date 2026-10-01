# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Analysis
    # @api private
    module TcpAnalysis
      # @rbs (Flow flow, Integer direction, TcpStream stream, Layer layer, Integer timestamp_ns) -> void
      def self.update(flow, direction, stream, layer, timestamp_ns)
        flags, seq, ack, length = layer[:flags], layer[:seq], layer[:ack], layer[:length]
        layer.add(:stream, 'tcp.stream', flow.id)
        layer.add(:seq_relative, 'tcp.seq_relative', Util::Seq.diff(seq, stream.base_seq || seq))
        peer = flow.streams[1 - direction]
        layer.add(:ack_relative, 'tcp.ack_relative', Util::Seq.diff(ack, peer.base_seq)) if peer && peer.base_seq && flags & 0x10 != 0
        keep_alive = stream.base_seq && flags & 7 == 0 && length <= 1 && seq == (stream.next_sequence - 1) % Util::Seq::MOD
        keep_alive_ack = flow.keep_alives[1 - direction] && peer && flags & 0x17 == 0x10 && length.zero? && ack == peer.next_sequence
        if flags & 0x10 != 0
          flag(layer, :duplicate_ack) if flags & 7 == 0 && length.zero? && layer[:window].positive? && flow.acks[direction] == [ack, layer[:window], 0] && !keep_alive_ack
          flow.acks[direction] = [ack, layer[:window], length]
          flow.keep_alives[1 - direction] = false
        end
        flag(layer, :zero_window) if layer[:window].zero? && flags & 6 == 0
        if keep_alive
          flag(layer, :keep_alive)
          flow.keep_alives[direction] = true
        end
        if flags & 2 != 0 && flags & 0x10 == 0
          flow.syn_ns ||= timestamp_ns
          flow.syn_direction ||= direction
        elsif flags & 0x12 == 0x12 && flow.syn_ns && flow.syn_direction != direction
          flow.synack_ns ||= timestamp_ns
          flow.synack_seq ||= seq
        elsif flags & 0x10 != 0 && flow.synack_ns && flow.syn_direction == direction && !flow.initial_rtt && ack == (flow.synack_seq + 1) % Util::Seq::MOD
          flow.initial_rtt = [timestamp_ns - flow.syn_ns, 0].max.fdiv(1_000_000_000)
        end
        layer.add(:initial_rtt, 'tcp.analysis.initial_rtt', flow.initial_rtt) if flow.initial_rtt && flags & 0x17 == 0x10
      end
      # @rbs (Layer layer, Symbol name) -> void
      def self.flag(layer, name) = layer.add("analysis_#{name}".to_sym, "tcp.analysis.#{name}", true, type: :boolean)
    end
  end
end
