# rbs_inline: enabled
# frozen_string_literal: true

require 'optparse'

module Redhound
  # @api private
  module CLI
    # @api private
    class Options
      attr_reader :values, :parser
      # @rbs (Array[String] argv) -> void
      def initialize(argv)
        @values = { interface: nil, read: nil, write: nil, count: nil, snaplen: 262144, promiscuous: true,
                    buffer_size: nil, direction: :inout, backend: :auto, filter: nil, format: nil,
                    packet_buffered: false, output: :summary, output_explicit: false, fields: Array.new, verbosity: 0,
                    link_layer: false, quick: false, timestamp: :clock, precision: :micro, resolve_names: false,
                    stats: Array.new, follow: nil, decode_as: Array.new, plugins: Array.new, dump: 0, debug: false, no_yjit: false }
        args = normalize(argv.dup)
        @parser = build_parser
        @parser.order!(args)
        filter = args.join(' ')
        if @values[:filter_file]
          raise ConfigurationError, 'cannot combine filter file and expression' unless filter.empty?
          filter = ::File.read(@values[:filter_file])
        end
        @values[:filter] = filter unless filter.strip.empty?
        validate
      rescue OptionParser::ParseError, ArgumentError => e
        raise ConfigurationError, e.message
      end

      # @rbs (Array[String] args) -> Array[String]
      def normalize(args)
        fields = args.each_cons(2).any? { |flag, value| %w[-T --output-format].include?(flag) && value == 'fields' } || args.include?('--output-format=fields')
        result = [] #: Array[String]
        while (arg = args.shift)
          if /\A-v{1,3}\z/.match?(arg)
            @values[:verbosity] += arg.length - 1
          elsif /\A-t{1,5}\z/.match?(arg)
            @values[:timestamp] = %i[none epoch delta date elapsed][arg.length - 2]
          elsif %w[-x -xx -X -XX].include?(arg)
            @values[:hex] = { ascii: arg.include?('X'), link_layer: arg.length == 3 }
          elsif arg == '-e'
            if fields
              field = args.shift
              raise ConfigurationError, '-e needs a field with -T fields' if !field || field.start_with?('-')
              @values[:fields] << field
            else
              @values[:link_layer] = true
            end
          else
            result << arg
          end
        end
        result
      end

      # @rbs () -> OptionParser
      def build_parser
        OptionParser.new do |o|
          o.banner = 'Usage: redhound [options] [filter expression]'
          o.on('-i', '--interface IF', 'interface name, index or any') { |v| @values[:interface] = v }
          o.on('-D', '--list-interfaces', 'list interfaces and exit') { @values[:list_interfaces] = true }
          o.on('-r', '--read FILE', 'read pcap or pcapng (- for stdin)') { |v| @values[:read] = v }
          o.on('-c', '--count N', Integer, 'stop after N packets') { |v| @values[:count] = v }
          o.on('-s', '--snaplen N', Integer, 'capture length (default 262144)') { |v| @values[:snaplen] = v.zero? ? 262144 : v }
          o.on('-p', '--no-promiscuous', 'disable promiscuous capture') { @values[:promiscuous] = false }
          o.on('-B', '--buffer-size KiB', Integer, 'kernel buffer size') { |v| @values[:buffer_size] = v * 1024 }
          o.on('-Q', '--direction DIR', %w[in out inout], 'capture direction') { |v| @values[:direction] = v.to_sym }
          o.on('-F', '--filter-file FILE', 'read a capture filter') { |v| @values[:filter_file] = v }
          o.on('--capture-backend BACKEND', %w[auto ring socket bpf], 'capture backend') { |v| @values[:backend] = v.to_sym }
          o.on('-w', '--write FILE', 'write capture (- for stdout)') { |v| @values[:write] = v }
          o.on('--format FORMAT', %w[pcap pcapng], 'capture file format') { |v| @values[:format] = v.to_sym }
          o.on('-C MB', Float, 'rotate after MB (decimal)') { |v| @values[:max_bytes] = (v * 1_000_000).to_i }
          o.on('-G SECONDS', Float, 'rotate at this interval') { |v| @values[:interval] = v }
          o.on('-W N', Integer, 'maximum rotation file count') { |v| @values[:file_count] = v }
          o.on('--post-rotate-command CMD', 'command to run after closing each file') { |v| @values[:post_rotate_command] = v }
          o.on('-U', '--packet-buffered', 'flush each packet') { @values[:packet_buffered] = true }
          o.on('-T', '--output-format FORMAT', %w[summary tree json ndjson fields], 'packet output format') do |v|
            @values[:output], @values[:output_explicit] = v.to_sym, true
          end
          o.on('-V', 'show packet details') { @values[:output], @values[:output_explicit] = :tree, true }
          o.on('-q', 'quick output and no capture statistics') { @values[:quick] = true }
          o.on('--time-stamp-precision PRECISION', %w[micro nano], 'timestamp digits') { |v| @values[:precision] = v.to_sym }
          o.on('-N', '--resolve-names', 'resolve addresses') { @values[:resolve_names] = true }
          o.on('-n', 'disable address resolution (default)') { @values[:resolve_names] = false }
          o.on('--stats SPEC', 'io,N / conv,TYPE / endpoints,TYPE / phs') { |v| @values[:stats] << v }
          o.on('--follow SPEC', 'tcp,ascii|hex|raw,N') { |v| @values[:follow] = v }
          o.on('--decode-as RULE', 'e.g. udp.port==8443,dns') { |v| @values[:decode_as] << v }
          o.on('-I', '--require FILE', 'load a custom dissector') { |v| @values[:plugins] << v }
          o.on('-d', 'dump cBPF instructions') { @values[:dump] += 1 }
          o.on('-Z', '--relinquish-privileges USER', 'drop capture privileges') { |v| @values[:user] = v }
          o.on('--list-protocols', 'list protocols and fields') { @values[:list_protocols] = true }
          o.on('--debug', 'print error backtraces') { @values[:debug] = true }
          o.on('--no-yjit', 'disable automatic YJIT activation') { @values[:no_yjit] = true }
          o.on('-h', '--help', 'print help') { @values[:help] = true }
          o.on('--version', 'print version') { @values[:version] = true }
          o.separator '  -e [-T fields: FIELD]   link header or selected field (repeatable)'
          o.separator '  -v / -vv / -vvv         verbosity and checksum verification'
          o.separator '  -t / -tt / -ttt / -tttt / -ttttt   timestamp style'
          o.separator '  -x / -xx / -X / -XX     hex dump, with link header / ASCII'
        end
      end

      # @rbs () -> void
      def validate
        %i[count snaplen buffer_size max_bytes interval file_count].each do |key|
          value = @values[key]
          raise ConfigurationError, "#{key} must be positive" if value && (!value.positive? || (value.respond_to?(:finite?) && !value.finite?))
        end
        raise ConfigurationError, 'snaplen exceeds 16 MiB' if @values[:snaplen] > 16 * 1024 * 1024
        raise ConfigurationError, 'choose either -r or -i' if @values[:read] && @values[:interface]
        raise ConfigurationError, 'rotation requires -w' if !@values[:write] && %i[max_bytes interval file_count post_rotate_command].any? { |k| @values[k] }
        raise ConfigurationError, '-W and post-rotate-command require -C or -G' if (@values[:file_count] || @values[:post_rotate_command]) && !@values[:max_bytes] && !@values[:interval]
        raise ConfigurationError, '-T fields requires at least one -e' if @values[:output] == :fields && @values[:fields].empty?
        raise ConfigurationError, 'cannot combine JSON/fields output and hex dump' if @values[:hex] && !%i[summary tree].include?(@values[:output])
        raise ConfigurationError, 'cannot display packets while writing capture to stdout' if @values[:write] == '-' && (@values[:output_explicit] || @values[:hex])
        if @values[:read] && @values[:write] && @values[:read] != '-' && @values[:write] != '-'
          input, output = @values[:read], @values[:write]
          if ::File.expand_path(input) == ::File.expand_path(output) || (::File.exist?(input) && ::File.exist?(output) && ::File.identical?(input, output))
            raise ConfigurationError, 'input and output must be different files'
          end
        end
        @values[:stats].each do |spec|
          valid = spec == 'phs' || /\A(?:conv|endpoints),(?:eth|ip|ipv6|tcp|udp)\z/.match?(spec) || /\Aio,(?:\d+(?:\.\d+)?)\z/.match?(spec) && spec.split(',').last.to_f.positive?
          raise ConfigurationError, "invalid statistics: #{spec}" unless valid
        end
        raise ConfigurationError, 'invalid TCP follow specification' if @values[:follow] && !/\Atcp,(?:ascii|hex|raw),\d+\z/.match?(@values[:follow])
      end
    end
  end
end
