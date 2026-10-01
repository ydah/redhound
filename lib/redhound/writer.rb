# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # Open pcap/pcapng outputs, optionally with bounded rotation.
  class Writer
    # @rbs (untyped output, ?linktype: Integer | Symbol | String, ?format: Symbol | String | nil, ?snaplen: Integer, ?precision: Symbol, ?packet_buffered: bool, ?forbidden_input: String?, **untyped options) -> untyped
    # @rbs [T] (untyped output, ?linktype: Integer | Symbol | String, ?format: Symbol | String | nil, ?snaplen: Integer, ?precision: Symbol, ?packet_buffered: bool, ?forbidden_input: String?, **untyped options) { (untyped) -> T } -> T
    # Open a path or binary IO; close automatically with a block. See docs/API.md for options.
    def self.open(output, linktype: :ethernet, format: nil, snaplen: 262_144, precision: :nano, packet_buffered: false, forbidden_input: nil, **options)
      if forbidden_input && forbidden_input != '-' && output.is_a?(String) && output != '-'
        same_path = ::File.expand_path(forbidden_input) == ::File.expand_path(output)
        same_file = ::File.exist?(forbidden_input) && ::File.exist?(output) && ::File.identical?(forbidden_input, output)
        raise ConfigurationError, 'input and output must be different files' if same_path || same_file
      end
      format ||= output.is_a?(String) && ::File.extname(output) == '.pcapng' ? :pcapng : :pcap
      raise ArgumentError, "unknown capture file format: #{format}" unless %i[pcap pcapng].include?(format.to_sym)

      options = options.merge(linktype:, format:, snaplen:, precision:, packet_buffered:, forbidden_input:)
      writer = if options[:max_bytes] || options[:interval]
                 File::RotatingWriter.new(output, **options)
               else
                 klass = format.to_sym == :pcapng ? File::PcapngWriter : File::PcapWriter
                 klass.new(output, **options)
               end
      return writer unless block_given?

      begin
        yield writer
      ensure
        writer.close
      end
    end
  end
end
