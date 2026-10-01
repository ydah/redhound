# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Analysis
    # @api private
    class TcpStream
      attr_reader :base_seq, :expected, :diagnostics, :deliveries, :gap_lengths, :fin
      # @rbs (?max_bytes: Integer) -> void
      def initialize(max_bytes: 1 << 20)
        raise ArgumentError, 'max_bytes must be positive' unless max_bytes.positive?
        @max_bytes, @expected, @history_start = max_bytes, 0, 0
        @highest = 0
        @base_seq = nil # @rbs Integer?
        @history = ''.b
        @queue = [] #: Array[untyped]
        @diagnostics, @deliveries, @gap_lengths = [], [], [] # @rbs untyped
        @fin, @fin_offset = false, nil # @rbs untyped
      end
      # @rbs (Integer sequence, String data, ?syn: bool, ?fin: bool, ?frame: Integer) -> Array[String]
      def push(sequence, data, syn: false, fin: false, frame: 0)
        @diagnostics, @deliveries, @gap_lengths = [], [], []
        unless @base_seq
          @base_seq = sequence
          @expected = syn ? 1 : 0
          @history_start = @expected
          @highest = @expected
        end
        base = @base_seq #: Integer
        start = @expected + Util::Seq.signed_diff(sequence, (base + @expected) % Util::Seq::MOD) + (syn ? 1 : 0)
        @fin_offset = start + data.bytesize if fin
        @diagnostics << :out_of_order if !data.empty? && start >= @expected && start < @highest
        @diagnostics << :lost_segment if !data.empty? && start > @highest
        @diagnostics << :retransmission if !data.empty? && start < @expected
        @highest = [@highest, start + data.bytesize + (fin ? 1 : 0)].max
        pieces = [[start, data, frame]]
        if start < @expected
          length = [data.bytesize, @expected - start].min
          compare_overlap(start, data, @history_start, @history)
          pieces = length >= data.bytesize ? Array.new : [[start + length, data.byteslice(length..), frame]] #: Array[untyped]
        end
        @queue.each do |old_start, old_data, _old_frame|
          replacement = [] #: Array[untyped]
          pieces.each do |pos, bytes, origin|
            compare_overlap(pos, bytes, old_start, old_data)
            ending, old_end = pos + bytes.bytesize, old_start + old_data.bytesize
            if pos < old_end && ending > old_start
              replacement << [pos, bytes.byteslice(0, old_start - pos), origin] if pos < old_start
              replacement << [old_end, bytes.byteslice(old_end - pos..), origin] if ending > old_end
            else
              replacement << [pos, bytes, origin]
            end
          end
          pieces = replacement
        end
        if !data.empty? && pieces.empty?
          @diagnostics.delete(:out_of_order)
          @diagnostics.delete(:lost_segment)
          @diagnostics << :retransmission unless @diagnostics.include?(:retransmission)
        end
        pieces.each do |piece|
          next if piece[1].empty?
          index = @queue.bsearch_index { |entry| entry[0] >= piece[0] } || @queue.length
          @queue.insert(index, piece)
        end
        drain
        while bytesize > @max_bytes || (@queue.first && @queue.first[0] - @expected > @max_bytes)
          break if @queue.empty?
          flush_gap(false)
        end
        trim_history
        if !@fin && @fin_offset && @expected >= @fin_offset
          @fin = true
          @expected += 1
        end
        @deliveries.filter_map(&:first)
      end

      # @rbs (Integer start, String data, Integer old_start, String old_data) -> void
      def compare_overlap(start, data, old_start, old_data)
        from = [start, old_start].max
        to = [start + data.bytesize, old_start + old_data.bytesize].min
        return unless from < to
        if data.byteslice(from - start, to - from) != old_data.byteslice(from - old_start, to - from) && !@diagnostics.include?(:overlap_mismatch)
          @diagnostics << :overlap_mismatch
        end
      end
      # @rbs () -> void
      def drain
        while @queue.first && @queue.first[0] == @expected
          pos, data, frame = @queue.shift
          @deliveries << [data, frame]
          @history_start = pos if @history.empty?
          @history << data
          @expected += data.bytesize
        end
      end
      # @rbs (?bool clear) -> Array[String]
      def flush_gap(clear = true)
        @deliveries, @gap_lengths = [], [] if clear
        return [] if @queue.empty?
        gap = @queue.first[0] - @expected
        if gap.positive?
          @diagnostics << :reassembly_gap
          @gap_lengths << gap
          @deliveries << [nil, gap]
          @expected += gap
          @history.clear
          @history_start = @expected
        end
        drain
        trim_history
        @deliveries.filter_map(&:first)
      end
      # @rbs () -> void
      def trim_history
        # Previously delivered bytes share the stream's bounded budget with holes.
        limit = [@max_bytes - @queue.sum { |item| item[1].bytesize + 128 }, 0].max
        excess = @history.bytesize - limit
        if excess.positive?
          @history = @history.byteslice(excess..) #: String
          @history_start += excess
        end
      end
      # @rbs () -> Integer
      def bytesize = @history.bytesize + @queue.sum { |item| item[1].bytesize + 128 }
      # @rbs () -> bool
      def pending? = !@queue.empty?
      # @rbs () -> Integer
      def next_sequence = ((@base_seq || 0) + @expected) % Util::Seq::MOD
      # @rbs () -> void
      def clear_deliveries = @deliveries.clear
    end
  end
end
