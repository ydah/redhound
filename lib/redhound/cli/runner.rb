# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module CLI
    # @api private
    class Runner
      # @rbs (Hash[Symbol, untyped] options, ?out: untyped, ?err: untyped) -> void
      def initialize(options, out: $stdout, err: $stderr)
        @options, @out, @err, @count = options, out, err, 0
        @source, @writer, @formatter, @analysis = nil, nil, nil, nil
        @handlers = {} #: Hash[String, untyped]
      end
      # @rbs () -> void
      def run
        opts = @options
        install_signals
        if opts[:dump].positive?
          if opts[:read]
            @source = read_capture { Redhound.open(opts[:read]) }
            linktype = read_capture { @source.next_packet }&.linktype || @source.linktype
          else
            linktype = opts[:interface] ? Capture::Interface.find(opts[:interface]).linktype : 1
          end
          program = Filter.compile(opts[:filter] || '', linktype: linktype, live: !opts[:read])
          @out.puts(program.disassemble(format: %i[text ruby decimal][[opts[:dump], 3].min - 1]))
          return
        end
        @source = if opts[:read]
                    read_capture { Redhound.open(opts[:read], filter: opts[:filter]) }
                  else
                    raise ConfigurationError, 'specify an interface with -i or capture file with -r' unless opts[:interface]
                    Capture.open(interface: opts[:interface], backend: opts[:backend], snaplen: opts[:snaplen],
                                 promiscuous: opts[:promiscuous], buffer_size: opts[:buffer_size], direction: opts[:direction], filter: opts[:filter])
                  end
        if opts[:write]
          @writer = Writer.open(opts[:write], linktype: @source.linktype, format: opts[:format], snaplen: opts[:snaplen],
                                precision: opts[:precision], packet_buffered: opts[:packet_buffered],
                                max_bytes: opts[:max_bytes], interval: opts[:interval], file_count: opts[:file_count],
                                post_rotate_command: opts[:post_rotate_command], forbidden_input: opts[:read], filter: opts[:filter])
        end
        display = !opts[:write] || opts[:output_explicit] || opts[:hex]
        @formatter = formatter if display && !opts[:follow]
        hex = opts[:hex] && Output::Hexdump.new(**opts[:hex])
        registry = Registry.default.copy
        opts[:decode_as].each { |rule| registry.decode_as(rule) }
        engine = Engine.new(registry: registry, verify_checksums: opts[:verbosity].positive?)
        if display || !opts[:stats].empty? || opts[:follow]
          @analysis = Analysis::Session.new(stats: opts[:stats], follow: opts[:follow], registry: registry)
        end
        Privileges.drop(opts[:user]) if opts[:user]
        until @stopping || @source.stopped?
          if @report_requested
            statistics
            @analysis&.snapshot(@err)
            @report_requested = false
          end
          packet = read_capture { @source.next_packet(timeout: 0.1) }
          next unless packet
          @writer&.write(packet)
          packet.engine = engine
          @analysis&.update(packet)
          @formatter&.format(packet, @out)
          hex&.format(packet, @out) if display
          @out.flush if opts[:packet_buffered] || @out.tty?
          @count += 1
          break if @stopping || (opts[:count] && @count >= opts[:count])
        end
      rescue RotationComplete, Interrupt
        nil
      ensure
        begin
          begin
            @formatter.finish(@out) if @formatter.respond_to?(:finish)
            @analysis&.finish(@out, @err)
            statistics if @source && !@options[:quick] && @options[:dump].zero?
            @writer.write_stats(@source.stats) if @writer && @source && @writer.respond_to?(:write_stats)
          ensure
            @writer&.close
          end
        ensure
          begin
            @source&.close
          ensure
            @handlers.each { |signal, handler| Signal.trap(signal, handler) }
          end
        end
      end
      # @rbs () -> untyped
      def formatter
        opts = @options
        case opts[:output]
        when :tree then Output::Tree.new
        when :json then Output::Json.new
        when :ndjson then Output::Json.new(ndjson: true)
        when :fields then Output::Fields.new(opts[:fields])
        else Output::Summary.new(timestamp: opts[:timestamp], precision: opts[:precision], link_layer: opts[:link_layer],
                                 quick: opts[:quick], verbosity: opts[:verbosity], resolve_names: opts[:resolve_names])
        end
      end
      # @rbs () -> void
      def install_signals
        %w[INT TERM].each do |signal|
          @handlers[signal] = Signal.trap(signal) do
            @stopping = true
            @source&.stop
            raise Interrupt if @options[:read] && @reading_capture
          end
        end
        %w[USR1 INFO].select { |s| Signal.list.key?(s) }.each do |signal|
          @handlers[signal] = Signal.trap(signal) { @report_requested = true }
        end
      end
      # @rbs [T] () { () -> T } -> T
      def read_capture
        @reading_capture = true
        yield
      ensure
        @reading_capture = false
      end
      # @rbs () -> void
      def statistics
        stats = @source.stats
        @err.puts("#{@count} packets captured", "#{stats.received} packets received by filter", "#{stats.dropped} packets dropped by kernel")
      end
    end
  end
end
