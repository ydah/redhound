# frozen_string_literal: true

require 'open3'
require 'stringio'
require_relative '../fixtures/generators/analysis'

RSpec.describe 'stateful analysis compared with tshark', :differential do
  include AnalysisFixtures

  def corpus(name) = File.expand_path("../fixtures/pcap/analysis-#{name}.pcap", __dir__)

  def tshark(name, *arguments)
    output, error, status = Open3.capture3('tshark', '-n', '-r', corpus(name), *arguments)
    expect(status.success?).to be(true), error
    output
  end

  def analyzed(name, **options)
    packets = Redhound.open(corpus(name)).to_a
    session = Redhound::Analysis::Session.new(**options)
    packets.each { |packet| session.update(packet) }
    [session, packets]
  end

  def reference_endpoint(text, type)
    return [text, 0] unless %i[tcp udp].include?(type)
    address, _colon, port = text.rpartition(':')
    [address, port.to_i]
  end

  before do
    skip 'tshark is not installed' unless system('tshark', '--version', out: File::NULL, err: File::NULL)
  end

  it 'reproduces all fixed analysis corpora from the generators' do
    { tcp: analysis_tcp_packets, stats: analysis_stats_packets, reassembly: analysis_reassembly_packets }.each do |name, packets|
      captured = Redhound.open(corpus(name)).to_a
      expect(captured.map { |packet| [packet.data, packet.timestamp_ns] }).to eq(packets.map { |packet| [packet.data, packet.timestamp_ns] })
    end
  end

  it 'matches TCP stream IDs, relative numbers, all six flags, and initial RTT' do
    flags = %w[retransmission out_of_order duplicate_ack zero_window keep_alive lost_segment]
    names = %w[frame.number tcp.stream tcp.seq tcp.ack tcp.analysis.initial_rtt] + flags.map { |name| "tcp.analysis.#{name}" }
    args = names.flat_map { |name| ['-e', name] }
    reference = tshark(:tcp, '-T', 'fields', *args).lines.map { |line| line.chomp.split("\t", -1) }
    session, packets = analyzed(:tcp, protocol_streams: false)
    packets.zip(reference).each do |packet, row|
      aggregate_failures("TCP frame #{packet.number}") do
        expect(packet['tcp.stream']).to eq(row[1].to_i)
        expect(packet['tcp.seq_relative']).to eq(row[2].to_i)
        expect(packet['tcp.ack_relative']).to eq(row[3].to_i) if packet['tcp.flags.ack']
        if row[4].empty?
          expect(packet['tcp.analysis.initial_rtt']).to be_nil
        else
          expect(packet['tcp.analysis.initial_rtt']).to be_within(1e-9).of(row[4].to_f)
        end
        flags.each_with_index do |name, index|
          expected = !row[index + 5].empty?
          expect(packet["tcp.analysis.#{name}"] == true).to eq(expected), "frame #{packet.number} #{name}"
        end
      end
    end
    session.finish(StringIO.new, StringIO.new)
  end

  it 'matches byte-for-byte follow output after retransmission, disorder, serial wrap and keepalive' do
    reference = tshark(:tcp, '-q', '-z', 'follow,tcp,raw,0').lines.filter_map do |line|
      hex = line.strip
      [hex].pack('H*') if hex.match?(/\A(?:[0-9a-f]{2})+\z/)
    end.join.b
    session, = analyzed(:tcp, follow: 'tcp,raw,0')
    output = StringIO.new(''.b)
    session.finish(output, StringIO.new)
    expect(output.string).to eq(reference)
    expect(output.string).to eq("ab\0\xffefghijklmnopqrst".b)
  end

  it 'matches DNS IP fragments and split HTTP, TLS and DNS TCP fields on completion frames' do
    names = %w[frame.number dns.qry.name http.host tls.handshake.extensions_server_name]
    reference = tshark(:reassembly, '-T', 'fields', *names.flat_map { |name| ['-e', name] }).lines.map { |line| line.chomp.split("\t", -1) }
    session, packets = analyzed(:reassembly)
    packets.zip(reference).each do |packet, row|
      names.drop(1).each_with_index do |name, index|
        expect(packet.field_values(name).map(&:to_s)).to eq(row[index + 1].empty? ? [] : row[index + 1].split(',')), "frame #{packet.number} #{name}"
      end
    end
    session.finish(StringIO.new, StringIO.new)
  end

  %i[eth ip ipv6 tcp udp].each do |type|
    it "matches #{type} conversation counts, bytes, start times and durations" do
      rows = tshark(:stats, '-q', '-z', "conv,#{type}").lines.filter_map do |line|
        parts = line.split
        next unless parts[1] == '<->'
        parts = parts.reject { |part| part == 'bytes' }
        a, b = reference_endpoint(parts[0], type), reference_endpoint(parts[2], type)
        key, direction = Redhound::Analysis::FlowKey.normalize(type, a, b)
        counts = [parts[5].to_i, parts[3].to_i, parts[6].to_i, parts[4].to_i]
        counts = [counts[1], counts[0], counts[3], counts[2]] if direction == 1
        [key, [*counts, (Rational(parts[9]) * 1_000_000_000).to_i, (Rational(parts[10]) * 1_000_000_000).to_i]]
      end.to_h
      session, packets = analyzed(:stats, stats: ["conv,#{type}"])
      actual = session.statistics.first.to_h[:rows].to_h do |row|
        key = [type, row[:addr_a], row[:port_a], row[:addr_b], row[:port_b]]
        [key, [*row.values_at(:packets_ab, :packets_ba, :bytes_ab, :bytes_ba), row[:start_ns] - packets.first.timestamp_ns, row[:duration_ns]]]
      end
      expect(actual).to eq(rows)
      session.finish(StringIO.new, StringIO.new)
    end

    it "matches #{type} endpoint send and receive counts and bytes" do
      reference = tshark(:stats, '-q', '-z', "endpoints,#{type}").lines.filter_map do |line|
        parts = line.split
        next unless parts[0]&.match?(/\A[0-9a-f:.]+\z/) && parts[1]&.match?(/\A\d+\z/)
        address = parts.shift
        port = %i[tcp udp].include?(type) ? parts.shift.to_i : 0
        [ [address, port], parts.drop(2).map(&:to_i) ]
      end.to_h
      session, = analyzed(:stats, stats: ["endpoints,#{type}"])
      actual = session.statistics.first.to_h[:rows].to_h do |row|
        [[row[:address], row[:port]], row.values_at(:packets_tx, :bytes_tx, :packets_rx, :bytes_rx)]
      end
      expect(actual).to eq(reference)
      session.finish(StringIO.new, StringIO.new)
    end
  end

  it 'matches interval and protocol hierarchy packet and byte counts' do
    reference = tshark(:stats, '-q', '-z', 'io,stat,1', '-z', 'io,phs')
    intervals = reference.lines.filter_map do |line|
      match = /\|\s*(\d+)\s*<>\s*(?:Dur|\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|/.match(line)
      [match[1].to_i, [match[2].to_i, match[3].to_i]] if match
    end.to_h
    path = []
    hierarchy = reference.lines.filter_map do |line|
      match = /\A( *)(\S+) +frames:(\d+) bytes:(\d+)/.match(line)
      next unless match
      depth = match[1].length / 2
      path = path.take(depth) + [match[2] == 'ip' ? :ipv4 : match[2].to_sym]
      [path, [match[3].to_i, match[4].to_i]]
    end.to_h
    session, = analyzed(:stats, stats: ['io,1', 'phs'])
    actual_intervals = session.statistics[0].to_h[:rows].to_h { |row| [row[:interval], row.values_at(:packets, :bytes)] }
    actual_hierarchy = session.statistics[1].to_h[:rows].to_h { |row| [row[:path], row.values_at(:packets, :bytes)] }
    expect(actual_intervals).to eq(intervals)
    expect(actual_hierarchy).to eq(hierarchy)
    session.finish(StringIO.new, StringIO.new)
  end
end
