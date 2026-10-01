#!/usr/bin/env ruby
# frozen_string_literal: true

# Controlled Linux traffic only; results never infer a completed elapsed-time gate.
require 'socket'
require 'json'
require 'optparse'
require 'fileutils'
require 'open3'
require 'digest'
require 'time'
require_relative 'live_traffic'

def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

if ARGV.first == '--send'
  _, namespace, port, duration, rate, start, result_path, templates_path, peer = ARGV
  port, rate, start, duration = Integer(port), Integer(rate), Float(start), Float(duration)
  count = 0
  batch = [rate / 1000, 1].max
  templates = templates_path ? RedhoundLiveTraffic.decode_templates(JSON.parse(File.read(templates_path))) : nil
  socket = if templates
             protocol = [0x0800].pack('n').unpack1('S')
             raw = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, protocol)
             address = [Socket::AF_PACKET, 0x0800, templates.fetch('peer_index'), 0, 0, 6,
                        PacketFactory.mac(templates.fetch('source_mac'))].pack('S n l S C C a8')
             raw.bind(address)
             raw
           else
             UDPSocket.new
           end
  begin
    socket.connect('10.123.0.1', port) unless templates
    delay = start - monotonic
    sleep(delay) if delay.positive?
    while count < (duration * rate).to_i && monotonic < start + duration
      [batch, (duration * rate).to_i - count].min.times do
        bytes = templates ? RedhoundLiveTraffic.frame(templates, count) : [count].pack('Q>') + RedhoundLiveTraffic::UDP_TAIL
        raise 'partial frame send' unless socket.send(bytes, 0) == bytes.bytesize
        count += 1
      end
      delay = start + count.fdiv(rate) - monotonic
      sleep(delay) if delay.positive?
    end
  ensure
    socket.close
  end
  File.write(result_path, JSON.pretty_generate(sent: count, elapsed: monotonic - start, rate: rate,
                                              workload: templates ? 'mixed_tcp_udp' : 'udp', peer: peer,
                                              protocol_counts: { udp: templates ? (count + 1) / 2 : count, tcp: templates ? count / 2 : 0 },
                                              cpu_affinity: File.read('/proc/self/status')[/^Cpus_allowed_list:\s+(.+)/, 1]))
  exit
end

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'redhound'
options = { duration: 10.0, rate: 1000, backends: %i[socket ring], out: 'tmp/live',
            rotate: false, verify_after: false, mixed: false, cpu: nil,
            rotation_interval: 60.0, sample: 10.0, buffer: 64 << 20 }
OptionParser.new do |parser|
  parser.banner = 'Usage: ruby --yjit bench/live.rb [options] (Linux, NET_RAW/NET_ADMIN/SYS_ADMIN)'
  parser.on('--duration SECONDS', Float) { |value| options[:duration] = value }
  parser.on('--rate PPS', Integer) { |value| options[:rate] = value }
  parser.on('--backend NAME', %w[compare socket ring]) { |value| options[:backends] = value == 'compare' ? %i[socket ring] : [value.to_sym] }
  parser.on('--out DIR') { |value| options[:out] = value }
  parser.on('--rotate', 'Bounded pcapng rotation; otherwise pcap writes go to /dev/null') { options[:rotate] = true }
  parser.on('--verify-after', 'Measure capture/write alone; verify saved pcap after capture ends') { options[:verify_after] = true }
  parser.on('--cpu CPU', Integer, 'Pin capture to this CPU and sender to another allowed CPU') { |value| options[:cpu] = value }
  parser.on('--mixed', 'Alternate valid 600-byte IPv4 TCP and UDP frames') { options[:mixed] = true }
  parser.on('--rotation-interval SECONDS', Float) { |value| options[:rotation_interval] = value }
  parser.on('--sample SECONDS', Float) { |value| options[:sample] = value }
end.parse!
abort 'Linux is required' unless RUBY_PLATFORM.include?('linux')
abort 'duration, rate and intervals must be finite and positive' unless options.values_at(:duration, :rate, :sample, :rotation_interval).all? { |value| value.positive? && value.finite? }
abort '--verify-after cannot be combined with rotation' if options[:verify_after] && options[:rotate]
abort 'CPU must be nonnegative' if options[:cpu] && options[:cpu].negative?
if options[:cpu]
  begin
    options[:original_cpu_affinity] = File.read('/proc/self/status')[/^Cpus_allowed_list:\s+(.+)/, 1]
    options[:capture_cpu_siblings] = File.read("/sys/devices/system/cpu/cpu#{options[:cpu]}/topology/thread_siblings_list").strip
    options[:sender_cpu] = RedhoundLiveTraffic.sender_cpu(options[:original_cpu_affinity], options[:cpu], options[:capture_cpu_siblings])
  rescue StandardError => error
    abort "cannot isolate sender CPU: #{error.message}"
  end
end
expected_records = (options[:duration] * options[:rate]).to_i
abort 'workload must include at least one frame' unless expected_records.positive?
expected_storage = options[:backends].size * (24 + expected_records * 616)
abort '--verify-after storage would exceed 4 GiB; reduce rate or duration, or verify inline' if options[:verify_after] && expected_storage > (4 << 30)
options[:workload] = options[:mixed] ? 'mixed_tcp_udp' : 'udp'
options[:frame_bytes], options[:expected_records] = 600, expected_records
options[:expected_storage_bytes] = options[:verify_after] ? expected_storage : 0
options[:capture_validation_deferred] = options[:verify_after]
abort 'result directory already exists; use a new --out directory' if File.exist?(File.join(options[:out], 'configuration.json'))
FileUtils.mkdir_p(options[:out], mode: 0o700)
capture_files = Dir[File.expand_path('../lib/redhound/{capture,file}/**/*.rb', __dir__)] + %w[capture.rb writer.rb packet.rb].map { |path| File.expand_path("../lib/redhound/#{path}", __dir__) }
code_sha256 = Digest::SHA256.hexdigest(capture_files.sort.map { |path| File.read(path) }.join)
harness_files = [__FILE__, File.expand_path('live_traffic.rb', __dir__), File.expand_path('../spec/support/packet_factory.rb', __dir__)]
harness_sha256 = Digest::SHA256.hexdigest(harness_files.map { |path| File.read(path) }.join)
File.write(File.join(options[:out], 'configuration.json'), JSON.pretty_generate(options.merge(ruby: RUBY_VERSION, platform: RUBY_PLATFORM, yjit: RubyVM::YJIT.enabled?, started_at: Time.now.utc.iso8601, capture_code_sha256: code_sha256, harness_sha256: harness_sha256)))
namespace, interface, peer = "rh-load-#{Process.pid}", "rh#{Process.pid}", "rp#{Process.pid}"
created_namespace = created_interface = false
children = []
ready_read, ready_write = IO.pipe
controls = []
Signal.trap('TERM') { raise Interrupt }

def ip(*args)
  output, error, status = Open3.capture3('ip', *args)
  raise "ip #{args.join(' ')}: #{output}#{error}" unless status.success?
  output
end

def validate_file(path)
  %w[capinfos tshark].each do |tool|
    args = tool == 'capinfos' ? [tool, '-c', path] : [tool, '-n', '-r', path, '-q']
    _output, error, status = Open3.capture3(*args)
    error = error.lines.reject { |line| line.start_with?('Running as user ') }.join
    raise "#{tool} rejected #{path}: #{error}" unless status.success? && error.empty?
  end
end

begin
  ip('netns', 'add', namespace)
  created_namespace = true
  ip('link', 'add', interface, 'type', 'veth', 'peer', 'name', peer)
  created_interface = true
  ip('link', 'set', peer, 'netns', namespace)
  ip('addr', 'add', '10.123.0.1/30', 'dev', interface)
  ip('link', 'set', interface, 'up')
  ip('netns', 'exec', namespace, 'ip', 'addr', 'add', '10.123.0.2/30', 'dev', peer)
  ip('netns', 'exec', namespace, 'ip', 'link', 'set', peer, 'up')
  receiver = UDPSocket.new
  receiver.bind('0.0.0.0', 0)
  port = receiver.addr[1]
  templates_path = nil
  templates = nil
  if options[:mixed]
    destination = JSON.parse(ip('-j', 'link', 'show', 'dev', interface)).fetch(0)
    origin = JSON.parse(ip('netns', 'exec', namespace, 'ip', '-j', 'link', 'show', 'dev', peer)).fetch(0)
    encoded = RedhoundLiveTraffic.templates(source_mac: origin.fetch('address'), destination_mac: destination.fetch('address'),
                                            port: port, peer_index: origin.fetch('ifindex'))
    templates_path = File.join(options[:out], 'templates.json')
    File.open(templates_path, 'wb', 0o600) { |file| file.write(JSON.pretty_generate(encoded)) }
    templates = RedhoundLiveTraffic.decode_templates(encoded)
  end

  options[:backends].each do |backend|
    control_read, control_write = IO.pipe
    controls << control_write
    children << fork do
      ready_read.close
      control_write.close
      source = writer = sample_io = sink = nil
      failed = false
      begin
        if options[:cpu]
          output, error, status = Open3.capture3('taskset', '-pc', options[:cpu].to_s, Process.pid.to_s)
          raise "cannot set capture CPU affinity: #{output}#{error}" unless status.success?
        end
        cpu_affinity = File.read('/proc/self/status')[/^Cpus_allowed_list:\s+(.+)/, 1]
        filter = options[:mixed] ? "(tcp or udp) and dst host 10.123.0.1 and dst port #{port}" : "udp dst port #{port}"
        source = Redhound::Capture.open(interface: interface, backend: backend, direction: :in,
                                       promiscuous: false, buffer_size: options[:buffer], filter: filter)
        writer = if options[:rotate]
                   Redhound::Writer.open(File.join(options[:out], "#{backend}.pcapng"), max_bytes: 64 << 20,
                                         interval: options[:rotation_interval], file_count: 3)
                 elsif options[:verify_after]
                   Redhound::Writer.open(File.join(options[:out], "#{backend}.pcap"))
                 else
                   sink = File.open(File::NULL, 'wb')
                   Redhound::Writer.open(sink)
                 end
        ready_write.puts(backend)
        ready_write.close
        timing = JSON.parse(control_read.gets)
        start = timing.fetch('start')
        control_read.close
        deadline = start + options[:duration] + 1
        count = 0
        last_capture_at = start
        verifier = RedhoundLiveTraffic::Verifier.new(start_ns: timing.fetch('realtime_ns'), duration: options[:duration],
                                                    templates: templates, port: port)
        next_sample = start
        sample_io = File.open(File.join(options[:out], "#{backend}-samples.jsonl"), 'wb', 0o600)
        max_rss = max_fds = 0
        while monotonic < deadline
          packet = source.next_packet(timeout: 0.1)
          if packet
            old_path = writer.path if options[:rotate]
            writer.write(packet)
            validate_file(old_path) if options[:rotate] && old_path != writer.path
            verifier.verify(packet) unless options[:verify_after]
            count += 1
            last_capture_at = monotonic
          end
          now = monotonic
          if now >= next_sample
            rss = File.read('/proc/self/status')[/^VmRSS:\s+(\d+)/, 1].to_i * 1024
            sample = { elapsed: now - start, rss: rss, fds: Dir.children('/proc/self/fd').size, captured: count, stats: source.stats.to_h }
            max_rss, max_fds = [max_rss, rss].max, [max_fds, sample[:fds]].max
            sample_io.puts(JSON.generate(sample))
            sample_io.flush
            File.write(File.join(options[:out], "#{backend}-progress.json"), JSON.pretty_generate(sample))
            next_sample = now + options[:sample]
          end
        end
        stats = source.stats
        writer.write_stats(stats)
        writer.close
        writer = nil
        if options[:verify_after]
          Redhound.open(File.join(options[:out], "#{backend}.pcap")) do |reader|
            reader.each { |packet| verifier.verify(packet) }
          end
          raise 'saved record count differs from captured count' unless verifier.count == count
        end
        Dir.glob(File.join(options[:out], "#{backend}_*.pcapng")).each { |path| validate_file(path) }
        elapsed = last_capture_at - start
        report = verifier.report.merge(backend: backend, captured: count, verification_passed: verifier.complete?(expected_records),
                   workload: options[:workload], frame_bytes: 600, cpu: options[:cpu], cpu_affinity: cpu_affinity,
                   sender_cpu: options[:sender_cpu], capture_cpu_siblings: options[:capture_cpu_siblings],
                   verify_after: options[:verify_after], capture_validation_deferred: options[:verify_after],
                   capture_code_sha256: code_sha256, harness_sha256: harness_sha256,
                   elapsed: elapsed, pps: count / elapsed, finish_lag: [elapsed - options[:duration], 0].max, stats: stats.to_h,
                   max_rss: max_rss, max_fds: max_fds)
        File.write(File.join(options[:out], "#{backend}.json"), JSON.pretty_generate(report))
      rescue StandardError, Interrupt => error
        warn error.full_message
        File.write(File.join(options[:out], "#{backend}-error.txt"), error.full_message) rescue nil
        failed = true
      ensure
        [writer, source, sample_io, sink].compact.each do |resource|
          begin
            resource.close
          rescue StandardError => error
            warn error.full_message
            failed = true
          end
        end
        exit!(failed ? 1 : 0)
      end
    end
    control_read.close
  end
  ready_write.close
  options[:backends].length.times { raise 'capture setup failed' unless ready_read.gets }
  ready_read.close
  start = monotonic + 0.5
  realtime_ns = Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond) + ((start - monotonic) * 1_000_000_000).round
  controls.each { |control| control.puts(JSON.generate(start: start, realtime_ns: realtime_ns)); control.close }
  sender_path = File.join(options[:out], 'sender.json')
  sender_command = ['ip', 'netns', 'exec', namespace, RbConfig.ruby, '--yjit', __FILE__, '--send', namespace,
                    port.to_s, options[:duration].to_s, options[:rate].to_s, start.to_s, sender_path]
  sender_command.concat([templates_path, peer]) if templates_path
  sender_command.unshift('taskset', '-c', options[:sender_cpu].to_s) if options[:sender_cpu]
  sender = Process.spawn(*sender_command)
  children << sender
  statuses = children.map { |pid| Process.wait2(pid).last }
  children.clear
  raise 'capture or sender failed; inspect error reports' unless statuses.all?(&:success?)
  sender_report = JSON.parse(File.read(sender_path))
  sent = sender_report.fetch('sent')
  reports = options[:backends].map { |backend| JSON.parse(File.read(File.join(options[:out], "#{backend}.json"))) }
  accepted = sent == expected_records && reports.all? do |report|
    report['captured'] == sent && report['verification_passed'] && report['stats']['received'] == sent &&
      report['stats']['dropped'].zero? && report['stats']['if_dropped'].zero? && report['finish_lag'] <= 0.1
  end
  accepted &&= sender_report['cpu_affinity'] == options[:sender_cpu].to_s if options[:sender_cpu]
  if reports.size == 2
    accepted &&= reports.map { |report| report['sha256'] }.uniq.size == 1
    stamps = reports.map { |report| report['timestamps'].to_h }
    accepted &&= stamps[0].keys == stamps[1].keys && stamps[0].all? { |sequence, time| (time - stamps[1][sequence]).abs <= 1_000_000 }
  end
  result = { passed: accepted, sent: sent, duration: options[:duration], requested_pps: options[:rate],
             workload: options[:workload], frame_bytes: 600, expected_records: expected_records, cpu: options[:cpu],
             sender_cpu: options[:sender_cpu], capture_cpu_siblings: options[:capture_cpu_siblings],
             original_cpu_affinity: options[:original_cpu_affinity],
             verify_after: options[:verify_after], capture_validation_deferred: options[:verify_after],
             capture_code_sha256: code_sha256, harness_sha256: harness_sha256,
             sender: sender_report, reports: reports.map { |report| report.reject { |key, _value| %w[samples timestamps].include?(key) } } }
  File.write(File.join(options[:out], 'result.json'), JSON.pretty_generate(result))
  puts JSON.pretty_generate(result)
  exit(accepted ? 0 : 1)
ensure
  controls.each { |control| control.close unless control.closed? }
  children.each do |pid|
    Process.kill('TERM', pid)
    Process.wait(pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end
  receiver&.close
  system('ip', 'link', 'del', interface, out: File::NULL, err: File::NULL) if created_interface
  system('ip', 'netns', 'del', namespace, out: File::NULL, err: File::NULL) if created_namespace
end
