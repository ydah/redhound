# frozen_string_literal: true
# rbs_inline: enabled

module Redhound
  # @api private
  module Filter
    # ASTs stay private; primitive operands are resolved before code generation.
    # @api private
    class Parser
      PROTOCOLS = %w[ether ip ip6 arp rarp tcp udp sctp icmp icmp6 igmp].freeze
      TYPES = %w[host net port portrange proto].freeze
      COMPARISONS = %w[= == != > >= < <=].freeze
      PRECEDENCE = { '|' => 1, '^' => 2, '&' => 3, '<<' => 4, '>>' => 4, '+' => 5, '-' => 5, '*' => 6, '/' => 6, '%' => 6 }.freeze
      CONSTANTS = { 'tcpflags' => 13, 'tcp-fin' => 1, 'tcp-syn' => 2, 'tcp-rst' => 4,
                    'tcp-push' => 8, 'tcp-ack' => 16, 'tcp-urg' => 32, 'tcp-ece' => 64, 'tcp-cwr' => 128,
                    'icmptype' => 0, 'icmpcode' => 1, 'icmp-echoreply' => 0, 'icmp-echo' => 8,
                    'icmp-unreach' => 3, 'icmp-timxceed' => 11 }.freeze

      # @rbs (String expression) -> void
      def initialize(expression)
        @expression = expression
        @tokens = Lexer.new(expression).tokens
        @index = 0
        @qualifier = nil #: untyped
      end

      # @rbs () -> untyped
      def parse
        return [:true] if peek.empty?
        ast = expression
        error("unexpected token #{peek.inspect}") unless peek.empty?
        ast
      end

      private

      # libpcap gives AND and OR the same precedence, left associative.
      # @rbs () -> untyped
      def expression
        node = unary
        while %w[and && or ||].include?(peek)
          operation = %w[and &&].include?(take) ? :and : :or
          node = [operation, node, unary]
        end
        node
      end

      # @rbs () -> untyped
      def unary
        if %w[not !].include?(peek)
          take
          return [:not, unary]
        end
        if peek == '(' || peek == '-' || numeric?(peek) || CONSTANTS.key?(peek)
          saved_index = @index
          begin
            return relation
          rescue FilterSyntaxError
            @index = saved_index
          end
          if peek == '('
            take
            node = expression
            expect(')')
            return node
          end
        end
        return relation if peek == 'len' || @tokens[@index + 1]&.first == '['

        primitive
      end

      # @rbs () -> untyped
      def primitive
        position = @tokens[@index][1]
        if %w[vlan greater less broadcast multicast].include?(peek)
          kind = take.to_sym
          value = %i[broadcast multicast].include?(kind) || (kind == :vlan && !numeric?(peek)) ? nil : number
          @qualifier = nil
          return [:primitive, nil, :either, kind, value, position]
        end
        proto = PROTOCOLS.include?(peek) ? take : nil
        if proto && %w[broadcast multicast].include?(peek)
          @qualifier = nil
          return [:primitive, proto, :either, take.to_sym, nil, position]
        end
        direction = nil
        if %w[src dst].include?(peek)
          direction = take.to_sym
          if %w[and or].include?(peek) && %w[src dst].include?(@tokens[@index + 1]&.first)
            operation = take
            other = take
            error('direction must combine src and dst') if other == direction.to_s
            direction = operation == 'and' ? :both : :either
          end
        end
        type = TYPES.include?(peek) ? take.to_sym : nil
        if proto && !direction && !type
          @qualifier = nil
          return [:primitive, proto, :either, :protocol, nil, position]
        end
        explicit = proto || direction || type
        qualifier = explicit ? [proto, direction || :either, type || :host] : @qualifier
        qualifier ||= [nil, :either, :host]
        @qualifier = qualifier
        if peek == '('
          take
          node = expression
          expect(')')
          return node
        end
        value = take
        error('expected a filter operand', position) if value.empty? || %w[and or && || )].include?(value)
        if qualifier[2] == :portrange && peek == '-'
          take
          value += '-' + take
        elsif qualifier[2] == :net && peek == 'mask'
          take
          value += ' mask ' + take
        end
        [:primitive, *qualifier, value, position]
      end

      # @rbs () -> untyped
      def relation
        left = arithmetic
        error('expected an arithmetic comparison') unless COMPARISONS.include?(peek)
        operator = take
        right = arithmetic
        @qualifier = nil
        [:relation, left, operator, right]
      end

      # @rbs (?Integer minimum) -> untyped
      def arithmetic(minimum = 0)
        position = @tokens[@index][1]
        value = take
        node = if value == '('
                 expression = arithmetic
                 expect(')')
                 expression
               elsif value == '-'
                 [:neg, arithmetic(7)]
               elsif value == 'len'
                 [:len]
               elsif CONSTANTS.key?(value)
                 [:number, CONSTANTS.fetch(value)]
               elsif numeric?(value)
                 [:number, integer(value)]
               elsif PROTOCOLS.include?(value) && peek == '['
                 take
                 offset = arithmetic
                 size = peek == ':' ? (take; number) : 1
                 expect(']')
                 error('byte accessor width must be 1, 2 or 4', position) unless [1, 2, 4].include?(size)
                 [:access, value, offset, size]
               else
                 error("invalid arithmetic operand #{value.inspect}", position)
               end
        while PRECEDENCE.fetch(peek, -1) >= minimum
          operation = take
          node = [:binary, operation, node, arithmetic(PRECEDENCE.fetch(operation) + 1)]
        end
        node
      end

      # @rbs (String value) -> bool
      def numeric?(value) = /\A(?:0[xX][\da-fA-F]+|\d+)\z/.match?(value)

      # @rbs (String value) -> Integer
      def integer(value)
        Integer(value, value.start_with?('0') && value.length > 1 ? 0 : 10)
      rescue ArgumentError
        error("invalid integer #{value.inspect}")
      end

      # @rbs () -> Integer
      def number
        value = take
        error("expected a number, got #{value.inspect}") unless numeric?(value)
        integer(value)
      end

      # @rbs () -> String
      def peek = @tokens[@index][0]

      # @rbs () -> String
      def take
        token = @tokens[@index][0]
        @index += 1 unless token.empty?
        token
      end

      # @rbs (String value) -> void
      def expect(value)
        error("expected #{value.inspect}, got #{peek.inspect}") unless peek == value
        take
      end

      # @rbs (String message, ?Integer? position) -> bot
      def error(message, position = nil)
        raise FilterSyntaxError.new(message, expression: @expression, position: position || @tokens[@index][1])
      end
    end
  end
end
