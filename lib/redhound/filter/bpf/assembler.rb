# frozen_string_literal: true
# rbs_inline: enabled

module Redhound
  # @api private
  module Filter
    # @api private
    module BPF
      # @api private
      class Assembler
        # @rbs () -> void
        def initialize
          @items = [] #: untyped
          @sequence = 0
        end

        # @rbs () -> Symbol
        def label
          @sequence += 1
          "label_#{@sequence}".to_sym
        end

        # @rbs (Symbol label) -> void
        def mark(label) = @items << [:label, label]

        # @rbs (Integer code, ?Integer k) -> void
        def emit(code, k = 0) = @items << [code, 0, 0, k & 0xffffffff]

        # @rbs (Symbol target) -> void
        def jump(target) = @items << [:jump, target]

        # @rbs (Integer code, Integer k, Symbol yes, Symbol no) -> void
        def branch(code, k, yes, no) = @items << [:branch, code, k & 0xffffffff, yes, no]

        # @rbs () -> Array[[Integer, Integer, Integer, Integer]]
        def assemble
          compact!
          widths = @items.map { |item| item[0] == :label ? 0 : 1 }
          labels = {} #: untyped
          loop do
            offset = 0
            @items.each_with_index do |item, index|
              labels[item[1]] = offset if item[0] == :label
              offset += widths[index]
            end
            raise FilterTooLarge, 'BPF programs are limited to 4096 instructions' if offset > 4096
            changed = false
            pc = 0
            @items.each_with_index do |item, index|
              if item[0] == :branch && widths[index] == 1 && [item[3], item[4]].any? { |target| labels.fetch(target) - pc - 1 > 255 }
                widths[index] = 3
                changed = true
              end
              pc += widths[index]
            end
            break unless changed
          end
          result = [] #: Array[[Integer, Integer, Integer, Integer]]
          @items.each_with_index do |item, index|
            pc = result.size
            case item[0]
            when :label then next
            when :jump then result << [5, 0, 0, labels.fetch(item[1]) - pc - 1]
            when :branch
              _, code, k, yes, no = item
              if widths[index] == 1
                result << [code, labels.fetch(yes) - pc - 1, labels.fetch(no) - pc - 1, k]
              else
                result << [code, 0, 1, k]
                result << [5, 0, 0, labels.fetch(yes) - pc - 2]
                result << [5, 0, 0, labels.fetch(no) - pc - 3]
              end
            else result << item
            end
          end
          result
        end

        private

        # Remove unreachable blocks and thread jumps through unconditional jumps.
        # @rbs () -> void
        def compact!
          labels = {} #: untyped
          @items.each_with_index { |item, index| labels[item[1]] = index if item[0] == :label }
          target = lambda do |name|
            index = labels.fetch(name) + 1
            index += 1 while @items[index]&.first == :label
            @items[index]&.first == :jump ? target.call(@items[index][1]) : name
          end
          @items.each do |item|
            item[1] = target.call(item[1]) if item[0] == :jump
            if item[0] == :branch
              item[3] = target.call(item[3])
              item[4] = target.call(item[4])
            end
          end
          reachable = {} #: Hash[Integer, bool]
          pending = [0]
          until pending.empty?
            index = pending.pop
            next if !index || index >= @items.size || reachable[index]
            reachable[index] = true
            item = @items[index]
            case item[0]
            when :jump then pending << labels.fetch(item[1])
            when :branch then pending.concat([labels.fetch(item[3]), labels.fetch(item[4])])
            when 6, 0x16 then next
            else pending << index + 1
            end
          end
          @items = @items.each_with_index.filter_map { |item, index| item if reachable[index] || item[0] == :label }
          @items = @items.each_with_index.filter_map do |item, index|
            following = @items[(index + 1)..].take_while { |next_item| next_item[0] == :label }
            item unless item[0] == :jump && following.any? { |label_item| label_item[1] == item[1] }
          end
        end
      end
    end
  end
end
