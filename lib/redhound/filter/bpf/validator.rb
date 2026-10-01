# frozen_string_literal: true
# rbs_inline: enabled

module Redhound
  # @api private
  module Filter
    # @api private
    module BPF
      # Validates the portable cBPF ISA and Linux VLAN ancillary loads.
      # @api private
      module Validator
        LOADS = [0x00, 0x20, 0x28, 0x30, 0x40, 0x48, 0x50, 0x60, 0x80,
                 0x01, 0x61, 0x81, 0xb1].freeze
        ALU = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x90, 0xa0].flat_map { |op| [op | 4, op | 12] }.freeze
        JUMPS = [0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d, 0x45, 0x4d].freeze
        OPCODES = (LOADS + ALU + JUMPS + [0x02, 0x03, 0x05, 0x06, 0x16, 0x07, 0x87, 0x84]).freeze

        # @rbs (Array[[Integer, Integer, Integer, Integer]] instructions) -> bool
        def self.validate!(instructions)
          raise FilterError, 'BPF instructions must be an Array' unless instructions.is_a?(Array)
          count = instructions.size
          raise FilterTooLarge, 'BPF programs are limited to 4096 instructions' if count > 4096
          raise FilterError, 'BPF program is empty' if count.zero?

          instructions.each_with_index do |instruction, index|
            unless instruction.is_a?(Array) && instruction.size == 4 && instruction.all? { |field| field.is_a?(Integer) }
              raise FilterError, "invalid BPF instruction #{index}"
            end
            code, jt, jf, k = instruction
            unless OPCODES.include?(code) && jt.between?(0, 255) && jf.between?(0, 255) && k.between?(0, 0xffffffff)
              raise FilterError, "invalid BPF opcode or operand at #{index}"
            end
            raise FilterError, "invalid scratch address at #{index}" if [0x60, 0x61, 2, 3].include?(code) && k > 15
            raise FilterError, "division by zero at #{index}" if [0x34, 0x94].include?(code) && k.zero?
            raise FilterError, "invalid shift at #{index}" if [0x64, 0x74].include?(code) && k > 31
            if [0x20, 0x28, 0x30].include?(code) && k >= 0xfffff000 && (code != 0x20 || ![0xfffff000, 0xfffff02c, 0xfffff030, 0xfffff03c].include?(k))
              raise FilterError, "unsupported ancillary load at #{index}"
            end
            successors(code, jt, jf, k, index).each do |target|
              raise FilterError, "invalid BPF jump at #{index}" unless target > index && target < count
            end
          end
          raise FilterError, 'BPF program must end with RET' unless [6, 0x16].include?(instructions.last[0])
          validate_memory!(instructions)
          true
        end

        # @rbs (Integer code, Integer jt, Integer jf, Integer k, Integer index) -> Array[Integer]
        def self.successors(code, jt, jf, k, index)
          return [] if [6, 0x16].include?(code)
          return [index + 1 + k] if code == 5
          return [index + 1 + jt, index + 1 + jf] if JUMPS.include?(code)

          [index + 1]
        end

        # @rbs (Array[[Integer, Integer, Integer, Integer]] instructions) -> void
        def self.validate_memory!(instructions)
          incoming = {} #: Hash[Integer, Integer]
          incoming[0] = 0
          instructions.each_with_index do |(code, jt, jf, k), index|
            initialized = incoming[index]
            next unless initialized
            if [0x60, 0x61].include?(code) && (initialized & (1 << k)).zero?
              raise FilterError, "uninitialized BPF scratch memory at #{index}"
            end
            initialized |= (1 << k) if [2, 3].include?(code)
            successors(code, jt, jf, k, index).each do |target|
              previous = incoming[target]
              incoming[target] = previous ? previous & initialized : initialized
            end
          end
        end
      end
    end
  end
end
