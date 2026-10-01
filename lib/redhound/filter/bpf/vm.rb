# frozen_string_literal: true
# rbs_inline: enabled

module Redhound
  # @api private
  module Filter
    # @api private
    module BPF
      # @api private
      class VM
        # @rbs (Array[[Integer, Integer, Integer, Integer]] instructions) -> void
        def initialize(instructions)
          Validator.validate!(instructions)
          @instructions = instructions
        end

        # @rbs (untyped packet) -> Integer
        def evaluate(packet)
          a = 0
          x = 0
          memory = Array.new(16, 0)
          pc = 0
          loop do
            code, jt, jf, k = @instructions.fetch(pc)
            pc += 1
            case code & 7
            when 0, 1
              value = case code & 0xe0
                      when 0 then k
                      when 0x60 then memory.fetch(k)
                      when 0x80 then packet.original_length
                      else
                        offset = k + ((code & 0xe0) == 0x40 ? x : 0)
                        if k >= 0xfffff000 && (code & 0xe0) == 0x20
                          ancillary(k, packet.meta)
                        else
                          size = { 0x00 => 4, 0x08 => 2, 0x10 => 1 }.fetch(code & 0x18)
                          return 0 if offset.negative? || offset + size > packet.data.bytesize
                          packet.data.unpack1({ 4 => 'N', 2 => 'n', 1 => 'C' }.fetch(size), offset: offset)
                        end
                      end
              if code == 0xb1
                x = (value & 15) * 4
              elsif (code & 7) == 1
                x = value & 0xffffffff
              else
                a = value & 0xffffffff
              end
            when 2 then memory[k] = a
            when 3 then memory[k] = x
            when 4
              operand = (code & 8).zero? ? k : x
              return 0 if [0x30, 0x90].include?(code & 0xf0) && operand.zero?
              a = arithmetic(code & 0xf0, a, operand) & 0xffffffff
            when 5
              if code == 5
                pc += k
              else
                operand = (code & 8).zero? ? k : x
                result = case code & 0xf0
                         when 0x10 then a == operand
                         when 0x20 then a > operand
                         when 0x30 then a >= operand
                         when 0x40 then (a & operand) != 0
                         end
                pc += result ? jt : jf
              end
            when 6 then return code == 0x16 ? a : k
            when 7
              code == 7 ? x = a : a = x
            end
          end
        end

        private

        # @rbs (Integer operation, Integer a, Integer operand) -> Integer
        def arithmetic(operation, a, operand)
          case operation
          when 0x00 then a + operand
          when 0x10 then a - operand
          when 0x20 then a * operand
          when 0x30 then a / operand
          when 0x40 then a | operand
          when 0x50 then a & operand
          when 0x60 then operand >= 32 ? 0 : a << operand
          when 0x70 then operand >= 32 ? 0 : a >> operand
          when 0x80 then -a
          when 0x90 then a % operand
          when 0xa0 then a ^ operand
          else 0
          end
        end

        # @rbs (Integer offset, untyped meta) -> Integer
        def ancillary(offset, meta)
          case offset
          when 0xfffff000 then meta.fetch(:protocol, 0)
          when 0xfffff030 then meta.key?(:vlan_tci) ? 1 : 0
          when 0xfffff02c then meta.fetch(:vlan_tci, 0)
          when 0xfffff03c then meta.fetch(:vlan_tpid, 0x8100)
          else 0
          end
        end
      end
    end
  end
end
