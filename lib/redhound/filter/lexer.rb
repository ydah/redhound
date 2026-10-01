# frozen_string_literal: true
# rbs_inline: enabled

module Redhound
  # @api private
  module Filter
    # @api private
    class Lexer
      # @rbs (String expression) -> void
      def initialize(expression)
        @expression = expression
      end

      # @rbs () -> Array[[String, Integer]]
      def tokens
        result = [] #: Array[[String, Integer]]
        position = 0
        brackets = 0
        while position < @expression.length
          tail = @expression[position..]
          if (space = /\A\s+/.match(tail))
            position += space[0].length
            next
          end
          patterns = [ /\A(?:&&|\|\||!=|==|>=|<=|<<|>>)/ ]
          if brackets.zero?
            patterns += [ /\A(?:[a-fA-F0-9]{1,2}:){5}[a-fA-F0-9]{1,2}/,
                          /\A(?=[a-fA-F0-9:.]*:)[a-fA-F0-9:.]+(?:\/\d+)?/,
                          /\A\d+(?:\.\d+){1,3}(?:\/\d+)?/ ]
          end
          patterns += [ /\A(?:0[xX][\da-fA-F]+|\d+)/,
                        /\A\\?[a-zA-Z_][a-zA-Z0-9_.-]*/, /\A[()\[\]:+*\/%&|^!<>=-]/ ]
          token = patterns.filter_map { |pattern| pattern.match(tail)&.[](0) }.first
          unless token
            raise FilterSyntaxError.new("unexpected character #{tail[0].inspect}", expression: @expression, position: position)
          end
          result << [token, position]
          brackets += 1 if token == '['
          brackets -= 1 if token == ']'
          position += token.length
        end
        result << ['', @expression.length]
      end
    end
  end
end
