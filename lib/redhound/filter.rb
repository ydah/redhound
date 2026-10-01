# frozen_string_literal: true
# rbs_inline: enabled

require_relative 'errors'
require_relative 'filter/bpf/validator'
require_relative 'filter/bpf/vm'
require_relative 'filter/bpf/disassembler'
require_relative 'filter/program'
require_relative 'filter/lexer'
require_relative 'filter/parser'
require_relative 'filter/analyzer'
require_relative 'filter/bpf/assembler'
require_relative 'filter/codegen'

module Redhound
  # @api private
  module Filter
    # Compiles a pcap-filter subset without libpcap or external commands.
    # @rbs (String expression, ?linktype: Symbol | Integer, ?snaplen: Integer, ?live: bool) -> Program
    def self.compile(expression, linktype: :ethernet, snaplen: 262_144, live: false)
      raise ArgumentError, 'filter expression must be a String' unless expression.is_a?(String)
      raise ArgumentError, 'snaplen must be between 1 and 16777216' unless snaplen.between?(1, 16_777_216)
      type = linktype.is_a?(Integer) ? linktype : CodeGen::LINKTYPES.fetch(linktype) { raise FilterError, "unknown linktype #{linktype}" }
      ast = Analyzer.new(expression).analyze(Parser.new(expression).parse)
      CodeGen.new(type, snaplen, live, expression).compile(ast)
    rescue SystemStackError
      raise FilterTooLarge, 'filter expression is too deeply nested'
    end
  end
end
