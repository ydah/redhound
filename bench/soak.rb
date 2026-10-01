#!/usr/bin/env ruby
# frozen_string_literal: true

# Actual-interface observation only. Elapsed time and traffic rates are evidence,
# not an automatic assertion that the interface met the "busy" acceptance gate.
require 'json'
require 'optparse'
require 'fileutils'
require 'open3'
require 'digest'
require 'time'
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'redhound'

module RedhoundSoak
  MAX_BYTES = 64 << 20
  FILE_COUNT = 3

  def self.monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  def self.options(argv)
    result = { interface: 'en0', backend: :auto, duration: 86_400.0, sample: 60.0,
               rotation_interval: 3600.0, out: "tmp/soak-#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}" }
    OptionParser.new do |parser|
      parser.banner = 'Usage: ruby bench/soak.rb --interface NAME [--duration SECONDS] [--out DIR]'
      parser.on('--interface NAME') { |value| result[:interface] = value }
      parser.on('--backend NAME', %w[auto socket ring bpf]) { |value| result[:backend] = value.to_sym }
      parser.on('--duration SECONDS', Float) { |value| result[:duration] = value }
      parser.on('--sample SECONDS', Float) { |value| result[:sample] = value }
      parser.on('--rotation-interval SECONDS', Float) { |value| result[:rotation_interval] = value }
      parser.on('--out DIR') { |value| result[:out] = value }
    end.parse!(argv)
    raise ArgumentError, 'unexpected positional arguments' unless argv.empty?
    unless result.values_at(:duration, :sample, :rotation_interval).all? { |value| value.finite? && value.positive? }
      raise ArgumentError, 'duration and intervals must be finite and positive'
    end
    result[:out] = File.expand_path(result[:out])
    result
  end

  def self.write_json(path, value)
    File.open(path, 'wb', 0o600) { |io| io.puts(JSON.pretty_generate(value)) }
  end

  def self.resources
    if RUBY_PLATFORM.include?('linux')
      { rss: File.read('/proc/self/status')[/^VmRSS:\s+(\d+)/, 1].to_i * 1024,
        fds: Dir.children('/proc/self/fd').size }
    else
      rss, rss_error, rss_status = Open3.capture3('ps', '-o', 'rss=', '-p', Process.pid.to_s)
      fds, fd_error, fd_status = Open3.capture3('/usr/sbin/lsof', '-a', '-p', Process.pid.to_s, '-Ff')
      raise "resource sampling failed: #{rss_error}#{fd_error}" unless rss_status.success? && fd_status.success?

      { rss: Integer(rss.strip) * 1024, fds: fds.lines.count { |line| line.match?(/\Af\d+\s*\z/) } }
    end
  end

  def self.validate_file(path)
    results = %w[capinfos tshark].map do |name|
      candidates = ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).map { |directory| File.join(directory, name) }
      candidates << "/Applications/Wireshark.app/Contents/MacOS/#{name}"
      executable = candidates.find { |candidate| File.file?(candidate) && File.executable?(candidate) }
      next { tool: name, passed: false, error: 'not installed; file validation remains pending' } unless executable

      args = name == 'capinfos' ? ['-c', path] : ['-n', '-r', path, '-q']
      output, error, status = Open3.capture3(executable, *args)
      error = error.lines.reject { |line| line.start_with?('Running as user ') }.join
      { tool: name, passed: status.success? && error.empty?, output:, error:, exit_status: status.exitstatus }
    end
    { path:, bytes: File.size(path), mode: format('%04o', File.stat(path).mode & 0o777),
      passed: results.all? { |result| result[:passed] }, tools: results }
  end

  def self.run(options)
    directory = options.fetch(:out)
    raise ArgumentError, 'output directory already exists; use a new --out directory' if File.exist?(directory)

    old_umask = File.umask(0o077)
    FileUtils.mkdir_p(directory, mode: 0o700)
    code = Dir[File.expand_path('../lib/**/*.rb', __dir__)].sort
    configuration = options.merge(pid: Process.pid, ruby: RUBY_VERSION, platform: RUBY_PLATFORM,
                                  requested_at: Time.now.utc.iso8601, max_bytes: MAX_BYTES, file_count: FILE_COUNT,
                                  source_sha256: Digest::SHA256.hexdigest(code.map { |path| File.binread(path) }.join),
                                  harness_sha256: Digest::SHA256.file(__FILE__).hexdigest)
    write_json(File.join(directory, 'configuration.json'), configuration)
    source = writer = samples = nil
    old_signals = {}
    begin
      source = Redhound::Capture.open(interface: options.fetch(:interface), backend: options.fetch(:backend),
                                     promiscuous: false)
      writer = Redhound::Writer.open(File.join(directory, 'capture.pcapng'), format: :pcapng,
                                    linktype: source.linktype, max_bytes: MAX_BYTES,
                                    interval: options.fetch(:rotation_interval), file_count: FILE_COUNT)
      stopped = false
      %w[INT TERM].each { |name| old_signals[name] = Signal.trap(name) { stopped = true; source.stop } }
      start = monotonic
      started_at = Time.now.utc
      deadline = start + options.fetch(:duration)
      configuration.merge!(started_at: started_at.iso8601, due_at: (started_at + options.fetch(:duration)).iso8601,
                           backend_class: source.class.name)
      write_json(File.join(directory, 'configuration.json'), configuration)
      samples = File.open(File.join(directory, 'samples.jsonl'), 'wb', 0o600)
      count = bytes = max_rss = max_fds = 0
      previous_time = start
      previous_count = previous_bytes = 0
      next_sample = start
      sample = lambda do |now|
        usage = resources
        interval = now - previous_time
        value = usage.merge(at: Time.now.utc.iso8601, elapsed: now - start, captured: count,
                            captured_original_bytes: bytes, interval_seconds: interval,
                            interval_pps: interval.positive? ? (count - previous_count) / interval : 0,
                            interval_bytes_per_second: interval.positive? ? (bytes - previous_bytes) / interval : 0,
                            stats: source.stats.to_h)
        samples.puts(JSON.generate(value))
        samples.flush
        write_json(File.join(directory, 'progress.json'), value)
        max_rss, max_fds = [max_rss, usage[:rss]].max, [max_fds, usage[:fds]].max
        previous_time, previous_count, previous_bytes = now, count, bytes
      end
      while !stopped && monotonic < deadline
        packet = source.next_packet(timeout: [deadline - monotonic, 0.1].min.clamp(0.0, 0.1))
        if packet
          writer.write(packet)
          count += 1
          bytes += packet.original_length
        end
        now = monotonic
        if now >= next_sample
          sample.call(now)
          next_sample = now + options.fetch(:sample)
        end
      end
      finish = monotonic
      sample.call(finish)
      stats = source.stats.to_h
      writer.write_stats(source.stats)
      writer.close
      writer = nil
      source.close
      source = nil
      files = Dir[File.join(directory, 'capture_*.pcapng')].sort.map { |path| validate_file(path) }
      elapsed = finish - start
      passed = !stopped && elapsed >= options.fetch(:duration) && stats[:dropped].zero? && files.all? { |file| file[:passed] }
      result = { passed:, completed_duration: !stopped && elapsed >= options.fetch(:duration), interrupted: stopped,
                 finished_at: Time.now.utc.iso8601, elapsed:, captured: count, captured_original_bytes: bytes,
                 average_pps: count / elapsed, average_bytes_per_second: bytes / elapsed,
                 busy_accepted: false, busy_note: 'Review measured traffic rates against the busy-interface requirement.',
                 stats:, max_rss:, max_fds:, files: }
      write_json(File.join(directory, 'result.json'), result)
      puts JSON.generate(result)
      passed
    rescue StandardError => error
      write_json(File.join(directory, 'result.json'), { passed: false, error: "#{error.class}: #{error.message}" })
      warn error.full_message
      false
    ensure
      old_signals.each { |name, handler| Signal.trap(name, handler) }
      [writer, source, samples].compact.each do |resource|
        resource.close
      rescue StandardError => error
        warn error.full_message
      end
      File.umask(old_umask)
    end
  end
end

exit(RedhoundSoak.run(RedhoundSoak.options(ARGV)) ? 0 : 1) if $PROGRAM_NAME == __FILE__
