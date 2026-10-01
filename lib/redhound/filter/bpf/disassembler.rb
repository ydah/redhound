# frozen_string_literal: true
# rbs_inline: enabled

module Redhound
  # @api private
  module Filter
    # @api private
    module BPF
      # @api private
      module Disassembler
        # @rbs (Array[[Integer, Integer, Integer, Integer]] instructions, ?format: Symbol) -> String
        def self.disassemble(instructions, format: :text)
          case format
          when :ruby
            "[\n" + instructions.map { |code, jt, jf, k| format('  [0x%04x, %d, %d, 0x%08x],', code, jt, jf, k) }.join("\n") + "\n]\n"
          when :decimal
            "#{instructions.size}\n" + instructions.map { |i| i.join(' ') }.join("\n") + "\n"
          when :text
            instructions.each_with_index.map do |(code, jt, jf, k), index|
              text = instruction(code, k)
              text += " jt #{index + jt + 1} jf #{index + jf + 1}" if Validator::JUMPS.include?(code)
              text = "ja #{index + k + 1}" if code == 5
              format('(%03d) %s', index, text)
            end.join("\n") + "\n"
          else raise ArgumentError, "unknown disassembly format #{format.inspect}"
          end
        end

        # @rbs (Integer code, Integer k) -> String
        def self.instruction(code, k)
          source = (code & 8).zero? ? "#0x#{k.to_s(16)}" : 'x'
          case code & 7
          when 0, 1
            mnemonic = (code & 7).zero? ? 'ld' : 'ldx'
            mnemonic += { 0 => '', 8 => 'h', 16 => 'b' }.fetch(code & 0x18)
            operand = case code & 0xe0
                      when 0 then "#0x#{k.to_s(16)}"
                      when 0x20 then "[#{k}]"
                      when 0x40 then "[x + #{k}]"
                      when 0x60 then "M[#{k}]"
                      when 0x80 then 'len'
                      when 0xa0 then "4*([#{k}]&0xf)"
                      end
            "#{mnemonic} #{operand}"
          when 2 then "st M[#{k}]"
          when 3 then "stx M[#{k}]"
          when 4
            "#{ { 0 => 'add', 0x10 => 'sub', 0x20 => 'mul', 0x30 => 'div', 0x40 => 'or', 0x50 => 'and', 0x60 => 'lsh', 0x70 => 'rsh', 0x80 => 'neg', 0x90 => 'mod', 0xa0 => 'xor' }.fetch(code & 0xf0)} #{source}"
          when 5 then "#{ { 0 => 'ja', 0x10 => 'jeq', 0x20 => 'jgt', 0x30 => 'jge', 0x40 => 'jset' }.fetch(code & 0xf0)} #{source}"
          when 6 then "ret #{code == 0x16 ? 'a' : "##{k}"}"
          when 7 then code == 7 ? 'tax' : 'txa'
          else raise FilterError, 'invalid BPF opcode'
          end
        end
      end
    end
  end
end
