# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Analysis
    # @api private
    class IpReassembler
      attr_reader :evicted, :expired
      # @rbs (?max_bytes: Integer, ?timeout_ns: Integer) -> void
      def initialize(max_bytes: 16 << 20, timeout_ns: 30_000_000_000)
        raise ArgumentError, 'fragment limits must be positive' unless max_bytes.positive? && timeout_ns.positive?
        @max_bytes, @timeout_ns, @clock, @evicted, @expired = max_bytes, timeout_ns, 0, 0, 0
        @next_sweep = 0
        @entries, @discarded = {}, {} # @rbs untyped
      end
      # @rbs (Packet packet) -> untyped
      def descriptor(packet)
        layers = packet.layers.reject(&:embedded)
        layers.each_with_index do |layer, index|
          if layer.protocol == :ipv4 && layer[:src] && layer[:dst] && (layer[:mf] == 1 || layer[:frag_offset].to_i.positive?)
            return [layer, layer, [4, layer[:src], layer[:dst], layer[:proto], layer[:id]], layer[:frag_offset], layer[:mf] == 1]
          elsif layer.protocol == :ipv6_ext && layer[:type] == 44 && layer[:fragment_offset] && layer[:identification]
            network = layers.take(index).reverse.find { |item| item.protocol == :ipv6 }
            return [network, layer, [6, network[:src], network[:dst], layer[:identification]], layer[:fragment_offset], layer[:more] == 1] if network && network[:src] && network[:dst]
          end
        end
        nil
      end
      # @rbs (Packet packet) -> Packet?
      def update(packet)
        advance(packet.timestamp_ns)
        info = descriptor(packet)
        return nil unless info
        network, fragment, key, offset, more = info
        return nil if @discarded[key]
        return nil if network.error? || fragment.error?
        length = network.payload_end - fragment.payload_offset
        if offset + length > 65_535 || length.negative? || (more && (length.zero? || length % 8 != 0))
          fragment.diagnose(:error, :malformed, 'invalid IP fragment size or offset')
          @entries.delete(key)
          return nil
        end
        if network.diagnostics.any? { |diagnostic| diagnostic.code == :truncated }
          fragment.diagnose(:note, :reassembly_gap, 'truncated IP fragment cannot be reassembled')
          return nil
        end
        data = packet.data.byteslice(fragment.payload_offset, length) #: String
        state = @entries.delete(key) || { parts: Array.new, frames: Array.new, header: nil, next_offset: 6, next: fragment[:next], end: nil } #: untyped
        if key[0] == 6 && state[:next] != fragment[:next]
          fragment.diagnose(:error, :malformed, 'IPv6 fragments have inconsistent next headers')
          return nil
        end
        state[:time] = @clock
        old_parts = state[:parts]
        overlap = old_parts.any? { |pos, bytes| offset < pos + bytes.bytesize && offset + length > pos }
        if overlap
          fragment.diagnose(:warning, :fragment_overlap, 'overlapping IP fragments')
          if key[0] == 6
            @discarded[key] = @clock
            while @discarded.size > [4096, @max_bytes / 128].min
              @discarded.shift
              @evicted += 1
            end
            while bytesize > @max_bytes && @entries.shift
              @evicted += 1
            end
            return nil
          end
        end
        pieces = [[offset, data]]
        old_parts.each do |pos, bytes|
          replacement = [] #: Array[untyped]
          pieces.each do |start, payload|
            ending, old_end = start + payload.bytesize, pos + bytes.bytesize
            if start < old_end && ending > pos
              from, to = [start, pos].max, [ending, old_end].min
              fragment.diagnose(:warning, :overlap_mismatch) if payload.byteslice(from - start, to - from) != bytes.byteslice(from - pos, to - from)
              replacement << [start, payload.byteslice(0, pos - start)] if start < pos
              replacement << [old_end, payload.byteslice(old_end - start..)] if ending > old_end
            else
              replacement << [start, payload]
            end
          end
          pieces = replacement
        end
        first_final = !more && !state[:end]
        unless more
          if state[:end] && state[:end] != offset + length
            fragment.diagnose(:error, :malformed, 'inconsistent final IP fragment length')
            return nil
          end
          state[:end] = offset + length
        end
        state[:frames] << packet.number if !pieces.empty? || first_final
        state[:parts].concat(pieces).sort_by!(&:first)
        if offset.zero? && !state[:header]
          state[:header] = packet.data.byteslice(network.offset, fragment.payload_offset - network.offset - (key[0] == 6 ? 8 : 0))
          if key[0] == 6
            position = packet.layers.index(fragment) #: Integer
            previous = packet.layers.take(position).last #: Layer
            state[:next_offset] = previous == network ? 6 : previous.offset - network.offset
          end
        end
        @entries[key] = state
        if complete?(state)
          @entries.delete(key)
          return virtual_packet(packet, state, key[0])
        end
        while bytesize > @max_bytes
          removed = @entries.shift
          break unless removed
          @evicted += 1
          fragment.diagnose(:warning, :reassembly_gap, 'IP reassembly memory limit exceeded')
        end
        nil
      end
      # @rbs (untyped state) -> bool
      def complete?(state)
        return false unless state[:header] && state[:end]
        expected = 0
        state[:parts].each do |offset, bytes|
          return false unless offset == expected
          expected += bytes.bytesize
        end
        expected == state[:end]
      end
      # @rbs (Packet packet, untyped state, Integer version) -> Packet?
      def virtual_packet(packet, state, version)
        payload = state[:parts].map(&:last).join.b
        header = state[:header].dup
        if header.bytesize + payload.bytesize > 65_535
          packet.layers.last.diagnose(:error, :bad_length, 'reassembled IP datagram exceeds 65535 bytes')
          return nil
        end
        if version == 4
          header[2, 2] = [header.bytesize + payload.bytesize].pack('n')
          header[6, 2] = [header.unpack1('n', offset: 6) & 0x4000].pack('n')
          header[10, 2] = "\0\0"
          header[10, 2] = [Protocols::Checksum.value(header)].pack('n')
        else
          header.setbyte(state[:next_offset], state[:next])
          header[4, 2] = [header.bytesize - 40 + payload.bytesize].pack('n')
        end
        result = Packet.new(header + payload, linktype: 101, timestamp_ns: packet.timestamp_ns, number: packet.number,
                            interface: packet.interface, direction: packet.direction,
                            meta: packet.meta.merge(reassembled_from: state[:frames].uniq.sort))
        result.engine = packet.engine
        result
      end
      # @rbs (Integer now_ns) -> void
      def advance(now_ns)
        @clock = [@clock, now_ns].max
        expire(@clock) if @clock >= @next_sweep
      end
      # @rbs (Integer now_ns) -> void
      def expire(now_ns)
        @next_sweep = now_ns + 1_000_000_000
        @entries.delete_if do |_key, state|
          stale = now_ns - state[:time] >= @timeout_ns
          @expired += 1 if stale
          stale
        end
        @discarded.delete_if { |_key, time| now_ns - time >= @timeout_ns }
      end
      # @rbs () -> Integer
      def bytesize
        @discarded.size * 128 + @entries.values.sum do |state|
          512 + (state[:header]&.bytesize || 0) + state[:frames].size * 32 + state[:parts].sum { |_pos, bytes| bytes.bytesize + 128 }
        end
      end
      # @rbs () -> Integer
      def size = @entries.size
    end
  end
end
