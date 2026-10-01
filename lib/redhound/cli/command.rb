# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module CLI
    # @api private
    class Command
      # @rbs (Array[String] argv, ?out: untyped, ?err: untyped) -> Integer
      def run(argv, out: $stdout, err: $stderr)
        options = Options.new(argv)
        values = options.values
        values[:plugins].each { |path| require ::File.expand_path(path) }
        if values[:help]
          out.puts(options.parser)
        elsif values[:version]
          out.puts("Redhound #{VERSION}")
        elsif values[:list_interfaces]
          Capture.interfaces.each { |i| out.puts("#{i.index}.#{i.name} [#{i.flags & 1 != 0 ? 'Up' : 'Down'}]#{i.mac ? " #{i.mac}" : ''}#{i.mtu ? " mtu #{i.mtu}" : ''}") }
        elsif values[:list_protocols]
          Registry.default.protocols.each_value do |klass|
            fields = klass.compiled_header&.definitions&.map(&:name) || []
            out.puts("#{klass.protocol_id}: #{klass.protocol_name} #{fields.join(' ')}")
          end
        else
          Runner.new(values, out: out, err: err).run
        end
        0
      rescue ConfigurationError, FilterError, ArgumentError => e
        err.puts("redhound: #{e.message}")
        if e.is_a?(FilterSyntaxError) && e.expression && e.position
          err.puts("  #{e.expression}", "  #{' ' * e.position}^")
        end
        2
      rescue Error, SystemCallError, IOError, SocketError, LoadError => e
        err.puts("redhound: #{e.message}")
        err.puts(e.backtrace) if values && (values[:debug] || ENV['REDHOUND_DEBUG'] == '1')
        1
      end
    end
  end
end
