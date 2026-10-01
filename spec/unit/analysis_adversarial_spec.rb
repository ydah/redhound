# frozen_string_literal: true

require 'stringio'
require 'objspace'
require_relative '../../lib/redhound/analysis'

RSpec.describe 'adversarial stateful analysis' do
  def frame(payload = ''.b, seq: 100, flags: 0x18, port: 9999, number: 1, timestamp_ns: 0)
    Redhound::Packet.new(ether(ipv4(tcp(payload, seq: seq, flags: flags, dport: port), proto: 6)),
                         number: number, timestamp_ns: timestamp_ns)
  end

  def ip_fragment(payload, offset:, more:, v6: false, number: 1, timestamp_ns: 0)
    if v6
      bytes = ipv6([17, 0, offset | (more ? 1 : 0), 7].pack('CCnN') + payload, next_header: 44)
    else
      bytes = ipv4(payload, id: 7)
      bytes[6, 2] = [offset / 8 | (more ? 0x2000 : 0)].pack('n')
    end
    Redhound::Packet.new(ether(bytes, type: v6 ? 0x86dd : 0x0800), number: number, timestamp_ns: timestamp_ns)
  end

  it 'reports and frees unfinished IP datagrams at EOF, including overlap tombstones' do
    session = Redhound::Analysis::Session.new
    fragment = ipv4(udp('abcdefgh'), id: 7)
    fragment[6, 2] = [0x2000].pack('n')
    session.update(Redhound::Packet.new(ether(fragment)))
    expect(session.ip_reassembler.size).to eq(1)
    error = StringIO.new
    session.finish(StringIO.new, error)
    expect(error.string).to include('reassembly_gap')
    expect(session.ip_reassembler.bytesize).to eq(0)
  end

  it 'reports unresolved TCP holes when idle expiration or flow-count LRU removes the flow' do
    [false, true].each do |expire|
      session = Redhound::Analysis::Session.new(max_flows: 1, protocol_streams: false)
      session.update(frame(seq: 99, flags: 2))
      session.update(frame('tail', seq: 150, number: 2))
      session.update(frame('new', port: 9998, timestamp_ns: expire ? 120_000_000_000 : 0))
      error = StringIO.new
      session.finish(StringIO.new, error)
      expect(error.string).to include('reassembly_gap')
      expect(expire ? session.flows.expired : session.flows.evicted).to eq(1)
    end
  end

  it 'accounts for retained Ruby buffer capacity rather than only occupied stream bytes' do
    stream = Redhound::Analysis::TcpStream.new(max_bytes: 1 << 20)
    stream.push(100, 'x' * 700_000)
    retained = ObjectSpace.memsize_of(stream.instance_variable_get(:@history))
    expect(stream.bytesize).to be >= retained
    expect(stream.bytesize).to be <= 1 << 20
  end

  it 'detects heuristic HTTP when its start line itself spans TCP segments' do
    session = Redhound::Analysis::Session.new
    session.update(frame(seq: 99, flags: 2))
    session.update(frame('GE', number: 2))
    final = frame("T / HTTP/1.1\r\nHost: example.test\r\n\r\n", seq: 102, number: 3)
    session.update(final)
    expect(final['http.host']).to eq('example.test')
    expect(final[:http].field_value('tcp.reassembled_from')).to eq([2, 3])
    session.finish(StringIO.new, StringIO.new)
  end

  it 'contains application callback exceptions on FIN and records a dissector diagnostic' do
    registry = Redhound::Registry.default.copy
    broken = Class.new(Redhound::Protocols::Http) do
      def self.protocol_id = :http
      def on_close(_flow, _direction) = raise('broken stream finalizer')
    end
    registry.register('tcp.port', 9999, broken)
    session = Redhound::Analysis::Session.new(registry: registry)
    session.update(frame("GET / HTTP/1.1\r\nHost: unfinished"))
    fin = frame(seq: 130, flags: 0x11, number: 2)
    expect { session.update(fin) }.not_to raise_error
    expect(fin.layers.flat_map { |layer| layer.diagnostics.map(&:code) }).to include(:dissector_bug)
    expect { session.finish(StringIO.new, StringIO.new) }.not_to raise_error
  end

  it 'marks retransmissions of SYN and FIN even when there is no payload' do
    session = Redhound::Analysis::Session.new(protocol_streams: false)
    session.update(frame(seq: 99, flags: 2))
    syn = frame(seq: 99, flags: 2, number: 2)
    session.update(syn)
    expect(syn['tcp.analysis.retransmission']).to eq(true)
    session.update(frame(seq: 100, flags: 0x11, number: 3))
    fin = frame(seq: 100, flags: 0x11, number: 4)
    session.update(fin)
    expect(fin['tcp.analysis.retransmission']).to eq(true)
    session.finish(StringIO.new, StringIO.new)
  end

  it 'processes IPv6 atomic fragments independently of queued fragments and overlap tombstones' do
    session = Redhound::Analysis::Session.new
    session.update(ip_fragment('abcdefgh', offset: 8, more: true, v6: true))
    atomic = ip_fragment(udp('atomic', dport: 9999), offset: 0, more: false, v6: true, number: 2)
    session.update(atomic)
    expect(atomic['udp.dstport']).to eq(9999)
    expect(session.ip_reassembler.size).to eq(1)
    session.update(ip_fragment('XXXXXXXX', offset: 8, more: true, v6: true, number: 3))
    expect(session.ip_reassembler.size).to eq(0)
    atomic = ip_fragment(udp('atomic', dport: 9999), offset: 0, more: false, v6: true, number: 4)
    session.update(atomic)
    expect(atomic['udp.dstport']).to eq(9999)
    session.finish(StringIO.new, StringIO.new)
    expect(session.ip_reassembler.bytesize).to eq(0)
  end

  it 'bounds fragmented datagrams under many identities, expires discard tombstones, and preserves IPv6 extension headers' do
    reassembler = Redhound::Analysis::IpReassembler.new(max_bytes: 4096)
    100.times do |number|
      bytes = ipv4('abcdefgh', id: number)
      bytes[6, 2] = [0x2000].pack('n')
      reassembler.update(Redhound::Packet.new(ether(bytes)))
      expect(reassembler.bytesize).to be <= 4096
    end
    expect(reassembler.evicted).to be > 0
    reassembler.expire(30_000_000_000)
    expect(reassembler.bytesize).to eq(0)

    reassembler = Redhound::Analysis::IpReassembler.new
    reassembler.update(ip_fragment('abcdefgh', offset: 0, more: true, v6: true))
    duplicate = ip_fragment('abcdefgh', offset: 0, more: true, v6: true)
    expect(reassembler.update(duplicate)).to be_nil
    expect(duplicate[:ipv6_ext].diagnostics.map(&:code)).to include(:fragment_overlap)
    reassembler.expire(30_000_000_000)
    expect(reassembler.bytesize).to eq(0)
    payload = udp('abcdefgh', dport: 9999)
    fragments = [[8, false, payload.byteslice(8..)], [0, true, payload.byteslice(0, 8)]]
    result = nil
    fragments.each_with_index do |(offset, more, data), index|
      hop = [44, 0, 1, 4, 0, 0, 0, 0].pack('C8')
      header = [17, 0, offset | (more ? 1 : 0), 7].pack('CCnN')
      bytes = ipv6(hop + header + data, next_header: 0)
      result = reassembler.update(Redhound::Packet.new(ether(bytes, type: 0x86dd), number: index + 1, timestamp_ns: 31_000_000_000))
    end
    expect(result['udp.dstport']).to eq(9999)
    expect(result['ipv6.nxt']).to eq(0)
    expect(result.layers_of(:ipv6_ext).first[:next]).to eq(17)
    expect(result.meta[:reassembled_from]).to eq([1, 2])
    expect(reassembler.bytesize).to eq(0)
  end

  it 'reassembles many deterministic segment permutations across serial wrap with exact follow bytes' do
    random = Random.new(17_029)
    30.times do
      stream = Redhound::Analysis::TcpStream.new(max_bytes: 8192)
      base = 0xffff_ff00
      stream.push(base, ''.b, syn: true)
      chunks = 20.times.map { random.bytes(random.rand(1..50)) }
      offset = 1
      segments = chunks.map do |chunk|
        result = [(base + offset) % (1 << 32), chunk]
        offset += chunk.bytesize
        result
      end
      received = segments.shuffle(random: random).flat_map { |seq, data| stream.push(seq, data) }.join.b
      expect(received).to eq(chunks.join.b)
      expect(stream.pending?).to eq(false)
      expect(stream.bytesize).to be <= 8192
    end
  end

  it 'skips billion-byte holes without allocating the gap and releases one-direction streams on RST' do
    session = Redhound::Analysis::Session.new(stream_bytes: 256, protocol_streams: false, follow: 'tcp,raw,0')
    session.update(frame(seq: 0, flags: 2))
    tail = frame('tail', seq: 1_000_000_000, number: 2)
    session.update(tail)
    expect(tail[:tcp].diagnostics.map(&:code)).to include(:reassembly_gap)
    expect(session.bytesize).to be <= Redhound::Analysis::Flow::BASE_BYTES + 256
    rst = frame(seq: 1_000_000_004, flags: 4, number: 3)
    session.update(rst)
    expect(session.flows.values.first.closed?).to eq(true)
    expect(session.flows.values.first.streams.first.bytesize).to eq(0)
    output = StringIO.new(''.b)
    session.finish(output, StringIO.new)
    expect(output.string).to eq('tail')
  end

  it 'evicts TCP state under the TCP budget without discarding unrelated UDP flows' do
    session = Redhound::Analysis::Session.new(tcp_bytes: 256, protocol_streams: false)
    session.update(Redhound::Packet.new(ether(ipv4(udp('datagram', dport: 9998)))))
    session.update(frame('x' * 200))
    expect(session.flows.values.map { |flow| flow.key.first }).to eq([:udp])
    expect(session.flows.tcp_bytesize).to eq(0)
    session.finish(StringIO.new, StringIO.new)
  end

  it 'includes empty IO intervals while bounding long idle spans' do
    statistic = Redhound::Analysis::Stats::Io.new(1, max_rows: 4)
    statistic.update(frame('a'))
    statistic.update(frame('b', timestamp_ns: 3_000_000_000))
    expect(statistic.to_h[:rows].map { |row| row[:packets] }).to eq([1, 0, 0, 1])
    statistic.update(frame('c', timestamp_ns: 1_000_000_000_000_000_000))
    expect(statistic.to_h[:rows].size).to be <= 4
    expect(statistic.bytesize).to be <= 4096
    expect(statistic.to_h[:rows].last[:packets]).to eq(1)
  end

  it 'keeps unknown IP transport protocols separate while retaining bidirectional keys' do
    session = Redhound::Analysis::Session.new
    [253, 254].each { |proto| session.update(Redhound::Packet.new(ether(ipv4('payload', proto: proto)))) }
    session.update(Redhound::Packet.new(ether(ipv4('reply', proto: 253, src: '192.0.2.2', dst: '192.0.2.1'))))
    expect(session.flows.size).to eq(2)
    expect(session.flows.values.map { |flow| flow.packets.sort }).to contain_exactly([0, 1], [1, 1])
    session.finish(StringIO.new, StringIO.new)
  end

  it 'rejects an empty or trailing-empty Content-Length immediately instead of waiting for a body' do
    ['1,', ''].each do |value|
      session = Redhound::Analysis::Session.new
      response = frame("HTTP/1.1 200 OK\r\nContent-Length: #{value}\r\n\r\n", port: 80)
      session.update(response)
      expect(response.layers_of(:http).flat_map { |layer| layer.diagnostics.map(&:code) }).to include(:malformed)
      expect(session.flows.values.first.applications.compact.sum(&:bytesize)).to eq(0)
      session.finish(StringIO.new, StringIO.new)
    end
  end

  it 'contains stream constructors and malformed callback results while preserving follow bytes' do
    [true, false].each do |constructor|
      registry = Redhound::Registry.default.copy
      broken = Class.new(Redhound::Protocols::Http) do
        def self.protocol_id = :http
      end
      if constructor
        broken.define_method(:initialize) { |**_options| raise 'broken stream constructor' }
      else
        broken.define_method(:on_data) { |_flow, _direction, _data, _frame| nil }
      end
      registry.register('tcp.port', 9999, broken)
      session = Redhound::Analysis::Session.new(registry: registry, follow: 'tcp,raw,0')
      captured = frame('payload')
      expect { session.update(captured) }.not_to raise_error
      expect(captured.layers.flat_map { |layer| layer.diagnostics.map(&:code) }).to include(:dissector_bug)
      output = StringIO.new(''.b)
      expect { session.finish(output, StringIO.new) }.not_to raise_error
      expect(output.string).to eq('payload')
    end
  end

  it 'releases all buffers and keeps the original error when stdout or stderr fails during finish' do
    [:stdout, :stderr].each do |destination|
      session = Redhound::Analysis::Session.new(follow: 'tcp,raw,0')
      session.update(frame("GET / HTTP/1.1\r\nHost: unfinished", port: 80))
      session.update(frame("GET / HTTP/1.1\r\nHost: unfinished", port: 8080))
      session.update(frame('GE'))
      session.update(ip_fragment('abcdefgh', offset: 0, more: true))
      failure = IOError.new("broken #{destination}")
      sink = Object.new
      sink.define_singleton_method(destination == :stdout ? :write : :puts) { |*_args| raise failure }
      output, errors = destination == :stdout ? [sink, StringIO.new] : [StringIO.new, sink]
      expect { session.finish(output, errors) }.to raise_error { |error| expect(error).to equal(failure) }
      expect(session.ip_reassembler.bytesize).to eq(0)
      expect(session.flows.tcp_bytesize).to eq(0)
      session.flows.values.each do |flow|
        expect(flow.streams.compact.sum(&:bytesize)).to eq(0)
        expect(flow.applications.compact.sum(&:bytesize)).to eq(0)
        expect(flow.probes).to all(be_empty)
        expect(flow.http_methods).to all(be_empty)
      end
      expect { session.finish(StringIO.new, StringIO.new) }.not_to raise_error
    end
  end

  it 'preserves an output error when closing the follow tempfile also fails' do
    session = Redhound::Analysis::Session.new(follow: 'tcp,raw,0')
    session.update(frame('follow bytes'))
    follow = session.instance_variable_get(:@follow)
    failure = IOError.new('broken stdout')
    sink = Object.new
    sink.define_singleton_method(:write) { |*_args| raise failure }
    follow.define_singleton_method(:close) { raise IOError, 'broken follow close' }
    expect { session.finish(sink, StringIO.new) }.to raise_error { |error| expect(error).to equal(failure) }
    expect(session.flows.tcp_bytesize).to eq(0)
  ensure
    follow&.instance_variable_get(:@file)&.close!
  end
end
