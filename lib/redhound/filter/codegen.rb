# frozen_string_literal: true
# rbs_inline: enabled

module Redhound
  # @api private
  module Filter
    # @api private
    class CodeGen
      LINKTYPES = { ethernet: 1, raw: 101, null: 0, loop: 108, linux_sll: 113, sll: 113,
                    linux_sll2: 276, sll2: 276, ipv4: 228, ipv6: 229 }.freeze
      LAYOUTS = { 1 => [14, 12], 113 => [16, 14], 276 => [20, 0], 0 => [4, 0],
                  108 => [4, 0], 101 => [0, nil], 12 => [0, nil], 228 => [0, nil], 229 => [0, nil] }.freeze
      ALU = { '+' => 0x00, '-' => 0x10, '*' => 0x20, '/' => 0x30, '|' => 0x40,
              '&' => 0x50, '<<' => 0x60, '>>' => 0x70, '%' => 0x90, '^' => 0xa0 }.freeze

      # @rbs (Integer linktype, Integer snaplen, bool live, String expression) -> void
      def initialize(linktype, snaplen, live, expression)
        @linktype = linktype
        @snaplen = snaplen
        @live = live
        @expression = expression
        @assembler = BPF::Assembler.new
        @shift = 0
        @dynamic_vlan = false
        @vlan_count = 0
        @network, @ethertype = LAYOUTS.fetch(linktype) { raise FilterError, "unsupported filter linktype #{linktype}" }
        @cooked_live = live && linktype == 276
        @network = 0 if @cooked_live
      end

      # @rbs (untyped ast) -> Program
      def compile(ast)
        if @live && @linktype == 1 && includes_vlan?(ast)
          @assembler.emit(0x00, 0)
          @assembler.emit(0x02, 15)
        end
        accepted = @assembler.label
        rejected = @assembler.label
        emit(ast, accepted, rejected)
        @assembler.mark(accepted)
        @assembler.emit(6, @snaplen)
        @assembler.mark(rejected)
        @assembler.emit(6, 0)
        Program.new(@assembler.assemble, linktype: @linktype, cooked_live: @cooked_live)
      end

      private

      # @rbs (untyped ast) -> bool
      def includes_vlan?(ast)
        return ast[3] == :vlan if ast[0] == :primitive
        return includes_vlan?(ast[1]) if ast[0] == :not
        return includes_vlan?(ast[1]) || includes_vlan?(ast[2]) if %i[and or].include?(ast[0])
        false
      end

      # @rbs (untyped node, Symbol yes, Symbol no) -> void
      def emit(node, yes, no)
        case node[0]
        when :true then @assembler.jump(yes)
        when :false then @assembler.jump(no)
        when :not then emit(node[1], no, yes)
        when :and, :or
          middle = @assembler.label
          emit(node[1], node[0] == :and ? middle : yes, node[0] == :and ? no : middle)
          @assembler.mark(middle)
          emit(node[2], yes, no)
        when :primitive
          if node[3] == :vlan
            vlan(node[4], yes, no)
          else
            emit(primitive(node), yes, no)
          end
        when :test
          _, offset, size, operation, value, mode = node
          load(offset, size, mode)
          compare(operation, value, yes, no)
        when :relation
          guards = access_protocols(node[1]) + access_protocols(node[3])
          guards.uniq.each do |protocol|
            next if protocol == 'ether'
            following = @assembler.label
            guard = if %w[ip ip6 arp rarp].include?(protocol)
                      family(protocol)
                    elsif protocol == 'icmp6'
                      conjunction(family('ip6'), next_protocol(6, 58))
                    else
                      conjunction(family('ip'), next_protocol(4, Analyzer::PROTOCOL_NUMBERS.fetch(protocol)), fragment_guard)
                    end
            emit(guard, following, no)
            @assembler.mark(following)
          end
          arithmetic(node[1], 0)
          if node[3][0] == :number
            compare(node[2], node[3][1], yes, no)
          else
            @assembler.emit(2, 0)
            arithmetic(node[3], 1)
            @assembler.emit(7)
            @assembler.emit(0x60, 0)
            compare(node[2], 0, yes, no, true)
          end
        else raise FilterError, "invalid filter AST #{node[0]}"
        end
      end

      # @rbs (untyped node) -> untyped
      def primitive(node)
        _, proto, direction, type, value, position = node
        case type
        when :protocol
          return @linktype == 1 ? [:true] : [:false] if proto == 'ether'
          return family(proto) if %w[ip ip6 arp rarp].include?(proto)
          number = Analyzer::PROTOCOL_NUMBERS.fetch(proto)
          return protocol(number, proto == 'icmp' || proto == 'igmp' ? [4] : proto == 'icmp6' ? [6] : [4, 6])
        when :proto
          return test(0xfffff000, 4, :eq, value, :absolute) if proto == 'ether' && @cooked_live
          return test(@ethertype.to_i + @shift, 2, :eq, value) if proto == 'ether' && @ethertype && ![0, 108].include?(@linktype)
          error('ether proto is unavailable for this linktype', position) if proto == 'ether'
          versions = proto == 'ip' ? [4] : proto == 'ip6' ? [6] : [4, 6]
          return protocol(value, versions)
        when :host, :net
          return ethernet_host(value.first, direction, position) if proto == 'ether'
          return addresses(value, proto, direction)
        when :port, :portrange then ports(value, direction)
        when :greater, :less then [:relation, [:len], type == :greater ? '>=' : '<=', [:number, value]]
        when :broadcast, :multicast then broadcast(proto, type, position)
        else raise FilterError, "unsupported filter primitive #{type}"
        end
      end

      # @rbs (String name) -> untyped
      def family(name)
        value = Analyzer::ETHER_TYPES.fetch(name)
        return test(0xfffff000, 4, :eq, value, :absolute) if @cooked_live
        if @ethertype && ![0, 108].include?(@linktype)
          test(@ethertype + @shift, 2, :eq, value)
        elsif [0, 108].include?(@linktype)
          return [:false] unless %w[ip ip6].include?(name)
          values = name == 'ip' ? [2] : [24, 28, 30]
          if @linktype.zero?
            values.map! do |v|
              word = [v].pack('L').unpack1('N') #: Integer
              word
            end
          end
          disjunction(*values.map { |v| test(0, 4, :eq, v, :absolute) })
        elsif name == 'ip' || name == 'ip6'
          version = name == 'ip' ? 4 : 6
          return [:false] if (@linktype == 228 && version != 4) || (@linktype == 229 && version != 6)
          [:relation, [:binary, '&', [:read, 0, 1, :absolute], [:number, 0xf0]], '=', [:number, version << 4]]
        else
          [:false]
        end
      end

      # @rbs (Integer number, Array[Integer] versions) -> untyped
      def protocol(number, versions)
        disjunction(*versions.map do |version|
          guard = next_protocol(version, number)
          if version == 6
            fragment = conjunction(next_protocol(6, 44), test(network + 40, 1, :eq, number))
            guard = disjunction(guard, fragment)
          end
          conjunction(family(version == 4 ? 'ip' : 'ip6'), guard)
        end)
      end

      # @rbs (Integer version, Integer number) -> untyped
      def next_protocol(version, number) = test(network + (version == 4 ? 9 : 6), 1, :eq, number)

      # @rbs () -> untyped
      def fragment_guard = test(network + 6, 2, :unset, 0x1fff)

      # @rbs () -> Integer
      def network = @network + @shift

      # @rbs (Integer offset, Integer size, Symbol operation, Integer value, ?Symbol? mode) -> untyped
      def test(offset, size, operation, value, mode = nil) = [:test, offset, size, operation, value, mode]

      # @rbs (*untyped nodes) -> untyped
      def conjunction(*nodes) = nodes.reduce { |left, right| [:and, left, right] } || [:true]

      # @rbs (*untyped nodes) -> untyped
      def disjunction(*nodes) = nodes.reduce { |left, right| [:or, left, right] } || [:false]

      # @rbs (Symbol direction, untyped src, untyped dst) -> untyped
      def directional(direction, src, dst)
        return src if direction == :src
        return dst if direction == :dst
        direction == :both ? conjunction(src, dst) : disjunction(src, dst)
      end

      # @rbs (untyped values, String? proto, Symbol direction) -> untyped
      def addresses(values, proto, direction)
        disjunction(*values.map do |version, address, mask|
          families = proto ? [proto] : version == 4 ? %w[ip arp rarp] : ['ip6']
          disjunction(*families.map do |name|
            src = network + (version == 6 ? 8 : %w[arp rarp].include?(name) ? 14 : 12)
            dst = network + (version == 6 ? 24 : %w[arp rarp].include?(name) ? 24 : 16)
            conjunction(family(name), directional(direction, address_test(src, version, address, mask), address_test(dst, version, address, mask)))
          end)
        end)
      end

      # @rbs (Integer offset, Integer version, Integer address, Integer mask) -> untyped
      def address_test(offset, version, address, mask)
        count = version == 6 ? 4 : 1
        conjunction(*(0...count).filter_map do |index|
          shift = (count - index - 1) * 32
          word_mask = (mask >> shift) & 0xffffffff
          next if word_mask.zero?
          expected = (address >> shift) & word_mask
          read = [:read, offset + index * 4, 4, nil]
          read = [:binary, '&', read, [:number, word_mask]] unless word_mask == 0xffffffff
          [:relation, read, '=', [:number, expected]]
        end)
      end

      # @rbs (String mac, Symbol direction, Integer position) -> untyped
      def ethernet_host(mac, direction, position)
        error('Ethernet addresses are unavailable for this linktype', position) unless @linktype == 1
        parts = mac.unpack('Nn') #: [Integer, Integer]
        src = conjunction(test(6, 4, :eq, parts[0], :absolute), test(10, 2, :eq, parts[1], :absolute))
        dst = conjunction(test(0, 4, :eq, parts[0], :absolute), test(4, 2, :eq, parts[1], :absolute))
        directional(direction, src, dst)
      end

      # @rbs (untyped ranges, Symbol direction) -> untyped
      def ports(ranges, direction)
        disjunction(*(ranges.flat_map do |number, limits|
          [4, 6].map do |version|
            guard = conjunction(family(version == 4 ? 'ip' : 'ip6'), next_protocol(version, number))
            guard = conjunction(guard, fragment_guard) if version == 4
            src = port_test(version, 0, limits)
            dst = port_test(version, 2, limits)
            conjunction(guard, directional(direction, src, dst))
          end
        end))
      end

      # @rbs (Integer version, Integer offset, [Integer, Integer] limits) -> untyped
      def port_test(version, offset, limits)
        mode = version == 4 ? :transport : nil
        location = network + (version == 4 ? offset : 40 + offset)
        low, high = limits
        return test(location, 2, :eq, low, mode) if low == high
        conjunction(test(location, 2, :ge, low, mode), test(location, 2, :le, high, mode))
      end

      # @rbs (String? proto, Symbol type, Integer position) -> untyped
      def broadcast(proto, type, position)
        if !proto || proto == 'ether'
          error('link broadcast/multicast requires Ethernet', position) unless @linktype == 1
          return type == :broadcast ? conjunction(test(0, 4, :eq, 0xffffffff, :absolute), test(4, 2, :eq, 0xffff, :absolute)) : test(0, 1, :set, 1, :absolute)
        end
        if proto == 'ip6'
          return conjunction(family('ip6'), test(network + 24, 1, :eq, 0xff))
        end
        condition = type == :broadcast ? disjunction(test(network + 16, 4, :eq, 0), test(network + 16, 4, :eq, 0xffffffff)) : test(network + 16, 1, :ge, 0xe0)
        conjunction(family('ip'), condition)
      end

      # @rbs (Integer? id, Symbol yes, Symbol no) -> void
      def vlan(id, yes, no)
        error('VLAN filtering requires Ethernet', 0) unless @linktype == 1
        tag_offset = 12 + @shift
        condition = disjunction(*[0x8100, 0x88a8, 0x9100].map { |type| test(tag_offset, 2, :eq, type) })
        condition = conjunction(condition, [:relation, [:binary, '&', [:read, tag_offset + 2, 2, nil], [:number, 0xfff]], '=', [:number, id]]) if id
        if @live && @vlan_count.zero?
          inline = @assembler.label
          metadata = @assembler.label
          @assembler.emit(0x20, 0xfffff030)
          @assembler.branch(0x15, 1, metadata, inline)
          @assembler.mark(metadata)
          if id
            @assembler.emit(0x20, 0xfffff02c)
            @assembler.emit(0x54, 0xfff)
            @assembler.branch(0x15, id, yes, no)
          else
            @assembler.jump(yes)
          end
          @assembler.mark(inline)
          @assembler.emit(0x00, 4)
          @assembler.emit(0x02, 15)
          emit(condition, yes, no)
          @dynamic_vlan = true
        elsif @dynamic_vlan
          matched = @assembler.label
          emit(condition, matched, no)
          @assembler.mark(matched)
          @assembler.emit(0x60, 15)
          @assembler.emit(0x04, 4)
          @assembler.emit(0x02, 15)
          @assembler.jump(yes)
        else
          emit(condition, yes, no)
          @shift += 4
        end
        @vlan_count += 1
      end

      # @rbs (Integer offset, Integer size, Symbol? mode) -> void
      def load(offset, size, mode)
        opcode = { 4 => 0x20, 2 => 0x28, 1 => 0x30 }.fetch(size)
        if mode == :transport
          transport_index
          @assembler.emit(opcode + 0x20, offset)
        elsif @dynamic_vlan && mode != :absolute
          @assembler.emit(0x61, 15)
          @assembler.emit(opcode + 0x20, offset)
        else
          @assembler.emit(opcode, offset)
        end
      end

      # @rbs () -> void
      def transport_index
        if @dynamic_vlan
          @assembler.emit(0x61, 15)
          @assembler.emit(0x50, network)
          @assembler.emit(0x54, 15)
          @assembler.emit(0x64, 2)
          @assembler.emit(0x0c)
          @assembler.emit(7)
        else
          @assembler.emit(0xb1, network)
        end
      end

      # @rbs (untyped operation, Integer value, Symbol yes, Symbol no, ?bool from_x) -> void
      def compare(operation, value, yes, no, from_x = false)
        code = case operation.to_s
               when 'eq', '=', '==' then 0x15
               when 'ne', '!=' then yes, no = no, yes; 0x15
               when 'gt', '>' then 0x25
               when 'ge', '>=' then 0x35
               when 'lt', '<' then yes, no = no, yes; 0x35
               when 'le', '<=' then yes, no = no, yes; 0x25
               when 'set' then 0x45
               when 'unset' then yes, no = no, yes; 0x45
               else raise FilterError, "unknown comparison #{operation}"
               end
        @assembler.branch(code | (from_x ? 8 : 0), value, yes, no)
      end

      # @rbs (untyped node) -> Array[String]
      def access_protocols(node)
        case node[0]
        when :access then [node[1]] + access_protocols(node[2])
        when :binary then access_protocols(node[2]) + access_protocols(node[3])
        when :neg then access_protocols(node[1])
        else []
        end
      end

      # @rbs (untyped node, Integer depth) -> void
      def arithmetic(node, depth)
        error('arithmetic expression requires more than 14 scratch registers', 0) if depth >= 14
        case node[0]
        when :number then @assembler.emit(0x00, node[1])
        when :len
          @assembler.emit(0x80)
          @assembler.emit(0x04, 20) if @cooked_live
        when :read then load(node[1], node[2], node[3])
        when :neg then arithmetic(node[1], depth); @assembler.emit(0x84)
        when :binary
          arithmetic(node[2], depth)
          if node[3][0] == :number
            @assembler.emit(ALU.fetch(node[1]) | 4, node[3][1])
          else
            @assembler.emit(2, depth)
            arithmetic(node[3], depth + 1)
            @assembler.emit(7)
            @assembler.emit(0x60, depth)
            @assembler.emit(ALU.fetch(node[1]) | 12)
          end
        when :access then accessor(node, depth)
        else raise FilterError, "invalid arithmetic AST #{node[0]}"
        end
      end

      # @rbs (untyped node, Integer depth) -> void
      def accessor(node, depth)
        _, protocol, offset, size = node
        transport = !%w[ether ip ip6 arp rarp icmp6].include?(protocol)
        base = protocol == 'ether' ? 0 : network + (protocol == 'icmp6' ? 40 : 0)
        if offset[0] == :number
          load(base + offset[1], size, transport ? :transport : protocol == 'ether' ? :absolute : nil)
        else
          arithmetic(offset, depth)
          @assembler.emit(2, depth)
          if transport
            transport_index
          elsif @dynamic_vlan && protocol != 'ether'
            @assembler.emit(0x61, 15)
          else
            @assembler.emit(0x01, 0)
          end
          @assembler.emit(0x60, depth)
          @assembler.emit(0x0c)
          @assembler.emit(7)
          @assembler.emit({ 4 => 0x40, 2 => 0x48, 1 => 0x50 }.fetch(size), base)
        end
      end

      # @rbs (String message, Integer position) -> bot
      def error(message, position)
        raise FilterSyntaxError.new(message, expression: @expression, position: position)
      end
    end
  end
end
