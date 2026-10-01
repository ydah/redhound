# frozen_string_literal: true
# rbs_inline: enabled
require 'ipaddr'
require 'socket'

module Redhound
  # @api private
  module Filter
    # @api private
    class Analyzer
      PROTOCOL_NUMBERS = { 'icmp' => 1, 'igmp' => 2, 'tcp' => 6, 'udp' => 17, 'ipv6' => 41,
                           'ipv6-frag' => 44, 'esp' => 50, 'ah' => 51, 'icmp6' => 58,
                           'ipv6-icmp' => 58, 'ospf' => 89, 'sctp' => 132 }.freeze
      ETHER_TYPES = { 'ip' => 0x0800, 'ip6' => 0x86dd, 'arp' => 0x0806, 'rarp' => 0x8035,
                      'vlan' => 0x8100 }.freeze

      # @rbs (String expression) -> void
      def initialize(expression)
        @expression = expression
      end

      # @rbs (untyped node) -> untyped
      def analyze(node)
        case node[0]
        when :and, :or then [node[0], analyze(node[1]), analyze(node[2])]
        when :not then [:not, analyze(node[1])]
        when :primitive then primitive(node)
        when :relation then [:relation, arithmetic(node[1]), node[2], arithmetic(node[3])]
        else node
        end
      end

      private

      # @rbs (untyped node) -> untyped
      def primitive(node)
        _, proto, direction, type, value, position = node
        error('unsupported qualifier combination', position) if %w[tcp udp sctp].include?(proto) && !%i[port portrange protocol].include?(type)
        case type
        when :port, :portrange
          error('ports require TCP, UDP or SCTP', position) if proto && !%w[tcp udp sctp].include?(proto)
          value = ports(value, proto, type, position)
        when :host, :net
          if proto == 'ether'
            error('Ethernet network qualifiers are unsupported', position) if type == :net
            error('expected a MAC address', position) unless /\A(?:[\da-fA-F]{1,2}:){5}[\da-fA-F]{1,2}\z/.match?(value)
            value = [value.split(':').map { |octet| octet.to_i(16) }.pack('C6')]
          else
            error('host qualifier requires ip, ip6, arp or rarp', position) if proto && !%w[ip ip6 arp rarp].include?(proto)
            value = addresses(value, type, position)
            value.select! { |family, _, _| proto == 'ip6' ? family == 6 : family == 4 } if proto
            error('address family does not match qualifier', position) if value.empty?
          end
        when :proto
          error('protocol qualifier cannot have a direction', position) unless direction == :either
          error('proto requires ip, ip6 or ether', position) if proto && !%w[ip ip6 ether].include?(proto)
          numbers = proto == 'ether' ? ETHER_TYPES : protocol_numbers
          value = integer_or_name(value, numbers, position)
          error('protocol number is out of range', position) unless value.between?(0, proto == 'ether' ? 65535 : 255)
        when :vlan
          error('VLAN ID is out of range', position) if value && !value.between?(0, 4095)
        when :greater, :less
          error('length is out of range', position) unless value.between?(0, 0xffffffff)
        when :broadcast, :multicast
          error('invalid broadcast/multicast protocol', position) if proto && !%w[ether ip ip6].include?(proto)
          error('IPv6 has no broadcast address', position) if type == :broadcast && proto == 'ip6'
        end
        [:primitive, proto, direction, type, value, position]
      end

      # @rbs (untyped node) -> untyped
      def arithmetic(node)
        case node[0]
        when :number
          error('arithmetic constant is out of range', 0) unless node[1].between?(0, 0xffffffff)
        when :binary
          node = [:binary, node[1], arithmetic(node[2]), arithmetic(node[3])]
          if %w[/ %].include?(node[1]) && node[3] == [:number, 0]
            error('division by zero', 0)
          end
          if %w[<< >>].include?(node[1]) && node[3][0] == :number && node[3][1] > 31
            error('shift count is out of range', 0)
          end
        when :neg then node = [:neg, arithmetic(node[1])]
        when :access then node = [:access, node[1], arithmetic(node[2]), node[3]]
        end
        node
      end

      # @rbs (String value, String? proto, Symbol type, Integer position) -> untyped
      def ports(value, proto, type, position)
        values = type == :port ? [value, value] : value.split('-', 2)
        error('portrange requires two port values', position) unless values.size == 2
        result = {} #: untyped
        candidates = proto ? [proto] : %w[tcp udp]
        candidates.each do |protocol|
          numbers = values.map do |part|
            if /\A(?:0x[\da-fA-F]+|\d+)\z/.match?(part)
              integer_or_name(part, {}, position)
            else
              error('expected a service name or port number', position) unless /\A[a-zA-Z][a-zA-Z0-9_-]*\z/.match?(part)
              begin
                Socket.getservbyname(part, protocol)
              rescue SocketError
                nil
              end
            end
          end
          next if numbers.any?(&:nil?)
          numbers = numbers.compact
          error('port number is out of range', position) unless numbers.all? { |port| port.between?(0, 65535) }
          result[PROTOCOL_NUMBERS.fetch(protocol)] = numbers.minmax
        end
        error('unknown service name', position) if result.empty?
        if !proto && result.values.uniq.size == 1
          result[132] = result.values.first
        end
        result
      end

      # @rbs (String value, Symbol type, Integer position) -> untyped
      def addresses(value, type, position)
        address_parts = value.split(' mask ', 2)
        address = address_parts.fetch(0)
        mask = address_parts[1]
        if /\A(?:\d+\.){0,3}\d+(?:\/\d+)?\z/.match?(address) || address.start_with?('0x')
          cidr_parts = address.split('/', 2)
          literal = cidr_parts.fetch(0)
          cidr = cidr_parts[1]
          octets = literal.split('.')
          if octets.size == 1
            number = integer_or_name(literal, {}, position)
            error('IPv4 address is out of range', position) unless number.between?(0, 0xffffffff)
            if type == :net && number <= 255
              number <<= 24
              prefix = 8
            else
              prefix = 32
            end
            ip = IPAddr.new([number].pack('N').unpack('C4').join('.'))
          else
            error('IPv4 octet is out of range', position) unless octets.all? { |part| part.to_i <= 255 }
            prefix = octets.size * 8
            ip = IPAddr.new((octets + Array.new(4 - octets.size, '0')).join('.'))
          end
          prefix = cidr.to_i if cidr
          error('CIDR requires a network qualifier', position) if type == :host && cidr && prefix != 32
          bitmask = mask ? IPAddr.new(mask).to_i : (0xffffffff << (32 - prefix)) & 0xffffffff
          error('invalid IPv4 netmask', position) unless prefix.between?(0, 32) && ((~bitmask & 0xffffffff) & ((~bitmask & 0xffffffff) + 1)).zero?
          error('non-network bits set in network address', position) if type == :net && (ip.to_i & bitmask) != ip.to_i
          return [[4, ip.to_i & bitmask, bitmask]]
        end
        if address.include?(':')
          ip = IPAddr.new(address)
          error('expected IPv6 address', position) unless ip.ipv6?
          prefix = address.include?('/') ? address.split('/').last.to_i : 128
          error('CIDR requires a network qualifier', position) if type == :host && prefix != 128
          return [[6, ip.to_i, ((1 << 128) - 1) ^ ((1 << (128 - prefix)) - 1)]]
        end
        error('network names must be numerical', position) if type == :net
        Addrinfo.getaddrinfo(address, nil, nil, Socket::SOCK_DGRAM).map do |info|
          ip = IPAddr.new(info.ip_address)
          [ip.ipv4? ? 4 : 6, ip.to_i, ip.ipv4? ? 0xffffffff : ((1 << 128) - 1)]
        end.uniq
      rescue IPAddr::Error, SocketError, ArgumentError => e
        error("invalid address #{value.inspect}: #{e.message}", position)
      end

      # @rbs (String value, Hash[String, Integer] names, Integer position) -> Integer
      def integer_or_name(value, names, position)
        value = value.delete_prefix('\\')
        return names.fetch(value.downcase) if names.key?(value.downcase)
        Integer(value, value.start_with?('0') && value.size > 1 ? 0 : 10)
      rescue ArgumentError
        error("unknown numeric value or name #{value.inspect}", position)
      end

      # @rbs () -> Hash[String, Integer]
      def protocol_numbers
        names = PROTOCOL_NUMBERS.dup
        if ::File.readable?('/etc/protocols')
          ::File.foreach('/etc/protocols') do |line|
            tokens = line.split('#', 2).first.to_s.split
            next unless tokens[1]&.match?(/\A\d+\z/)
            ([tokens[0]] + tokens.drop(2)).each { |name| names[name] = tokens[1].to_i }
          end
        end
        names
      end

      # @rbs (String message, Integer position) -> bot
      def error(message, position)
        raise FilterSyntaxError.new(message, expression: @expression, position: position)
      end
    end
  end
end
