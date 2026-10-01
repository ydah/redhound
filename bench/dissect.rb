#!/usr/bin/env ruby
# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'redhound'
require 'optparse'
options = { format: :summary }
OptionParser.new do |parser|
  parser.on('--format FORMAT', %w[summary tree filter write]) { |value| options[:format] = value.to_sym }
end.parse!
path = ARGV.fetch(0, 'tmp/bench.pcap')
formatter = options[:format] == :tree ? Redhound::Output::Tree.new : Redhound::Output::Summary.new(timestamp: :none)
program = Redhound::Filter.compile('tcp or udp') if options[:format] == :filter
count = 0
started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
File.open(File::NULL, 'wb') do |sink|
  writer = Redhound::Writer.open(sink) if options[:format] == :write
  Redhound.open(path) do |reader|
    reader.each do |packet|
      case options[:format]
      when :filter then program.match?(packet)
      when :write then writer.write(packet)
      else formatter.format(packet, sink)
      end
      count += 1
    end
  end
  writer&.close
end
elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
puts format('%s: %d pps (%d packets, %.3f s, Ruby %s, %s, YJIT %s)', options[:format], count / elapsed, count, elapsed, RUBY_VERSION, RUBY_PLATFORM, RubyVM::YJIT.enabled?)
