# frozen_string_literal: true
# rbs_inline: enabled

module Redhound
  # @api private
  module Filter
    # @api private
    class Program
      KernelPacket = Struct.new(:data, :original_length, :meta)
      attr_reader :instructions # : Array[[Integer, Integer, Integer, Integer]]
      attr_reader :linktype # : Integer?

      # @rbs (Array[[Integer, Integer, Integer, Integer]] instructions, ?linktype: Integer?, ?cooked_live: bool) -> void
      def initialize(instructions, linktype: nil, cooked_live: false)
        BPF::Validator.validate!(instructions)
        @instructions = instructions.map { |instruction| instruction.dup.freeze }.freeze
        @linktype = linktype
        @cooked_live = cooked_live
        @vm = BPF::VM.new(@instructions)
      end

      # @rbs (untyped packet) -> Integer
      def evaluate(packet)
        return 0 if linktype && packet.linktype != linktype

        if @cooked_live
          return 0 if packet.data.bytesize < 20
          protocol = packet.data.unpack1('n')
          packet = KernelPacket.new(packet.data.byteslice(20..), packet.original_length - 20, packet.meta.merge(protocol: protocol))
        end
        @vm.evaluate(packet)
      end

      # @rbs (untyped packet) -> bool
      def match?(packet) = evaluate(packet).positive?

      # Native struct sock_filter / struct bpf_insn bytes.
      # @rbs () -> String
      def packed = instructions.map { |instruction| instruction.pack('SCCL') }.join

      alias serialize packed
      alias to_binary packed

      # @rbs (?format: Symbol) -> String
      def disassemble(format: :text) = BPF::Disassembler.disassemble(instructions, format: format)

      # Includes a String reference retained by pack('P') until setsockopt/ioctl finishes.
      # @rbs () -> String
      def sock_fprog
        pointer_size = [nil].pack('P').bytesize
        [instructions.size, packed].pack("S x#{pointer_size - 2} P")
      end
    end
  end
end
