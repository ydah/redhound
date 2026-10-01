# frozen_string_literal: true

require 'stringio'
require 'json'
require 'json_schemer'
require_relative '../fixtures/generators/applications'
require_relative '../../lib/redhound/analysis'

RSpec.describe 'stateful analysis' do
  include ApplicationFixtures

  def packet(payload = ''.b, seq: 100, ack: 0, flags: 0x18, reverse: false, port: 80, number: 1, timestamp_ns: 0, window: 64_240)
    segment = tcp(payload, sport: reverse ? port : 40_000, dport: reverse ? 40_000 : port, seq: seq, ack: ack, flags: flags, window: window)
    Redhound::Packet.new(ether(ipv4(segment, proto: 6, src: reverse ? '192.0.2.2' : '192.0.2.1', dst: reverse ? '192.0.2.1' : '192.0.2.2')),
                         number: number, timestamp_ns: timestamp_ns)
  end

  def fragment(payload, offset:, more:, number: 1, ipv6: false)
    if ipv6
      bytes = self.ipv6([17, 0, offset | (more ? 1 : 0), 7].pack('CCnN') + payload, next_header: 44)
      Redhound::Packet.new(ether(bytes, type: 0x86dd), number: number)
    else
      bytes = ipv4(payload, id: 7)
      bytes[6, 2] = [(offset / 8) | (more ? 0x2000 : 0)].pack('n')
      Redhound::Packet.new(ether(bytes), number: number)
    end
  end

  it 'normalizes both directions, expires closed TCP, and evicts the least recently used flow' do
    table = Redhound::Analysis::FlowTable.new(max_flows: 2)
    first, direction = table.update(packet(flags: 2))
    same, reverse = table.update(packet(reverse: true, flags: 0x12))
    expect(same).to equal(first)
    expect(direction).not_to eq(reverse)
    table.update(packet(port: 81))
    table.update(packet(port: 82))
    expect(table.size).to eq(2)
    expect(table.evicted).to eq(1)
    flow, = table.update(packet(port: 82, flags: 4))
    expect(flow.closed?).to eq(true)
    table.expire(11_000_000_000)
    expect(table.size).to eq(1)
  end

  it 'reassembles out-of-order IPv4 and IPv6 without changing captured bytes' do
    [false, true].each do |v6|
      bytes = udp('abcdefghijk', dport: 9999)
      reassembler = Redhound::Analysis::IpReassembler.new
      tail = fragment(bytes.byteslice(8..), offset: 8, more: false, number: 2, ipv6: v6)
      head = fragment(bytes.byteslice(0, 8), offset: 0, more: true, number: 1, ipv6: v6)
      original = head.data.dup
      expect(reassembler.update(tail)).to be_nil
      result = reassembler.update(head)
      expect(result['udp.dstport']).to eq(9999)
      expect(result.meta[:reassembled_from]).to eq([1, 2])
      expect(head.data).to eq(original)
      expect(reassembler.bytesize).to be <= 128
    end
  end

  it 'keeps first IPv4 overlap bytes and discards all IPv6 overlaps' do
    [false, true].each do |v6|
      reassembler = Redhound::Analysis::IpReassembler.new
      reassembler.update(fragment(udp('abcdefgh', dport: 9999), offset: 0, more: true, ipv6: v6))
      overlapping = fragment('XXXXXXXX', offset: 8, more: false, number: 2, ipv6: v6)
      result = reassembler.update(overlapping)
      expect(overlapping.layers.flat_map { |layer| layer.diagnostics.map(&:code) }).to include(:fragment_overlap)
      expect(v6 ? result : result['udp.dstport']).to eq(v6 ? nil : 9999)
      expect(reassembler.bytesize).to be <= 128
    end
  end

  it 'tracks serial wrap, reorders segments, and diagnoses conflicting retransmissions' do
    session = Redhound::Analysis::Session.new(follow: 'tcp,raw,0')
    session.update(packet(seq: 0xffff_fffc, flags: 2))
    session.update(packet('ef', seq: 1, number: 3))
    session.update(packet('abcd', seq: 0xffff_fffd, number: 2))
    repeated = packet('XYcd', seq: 0xffff_fffd, number: 4)
    session.update(repeated)
    expect(repeated['tcp.analysis.retransmission']).to eq(true)
    expect(repeated[:tcp].diagnostics.map(&:code)).to include(:overlap_mismatch)
    expect(repeated['tcp.seq']).to eq(0xffff_fffd)
    expect(repeated['tcp.seq_relative']).to eq(1)
    out = StringIO.new(''.b)
    session.finish(out, StringIO.new)
    expect(out.string).to eq('abcdef')
  end

  it 'preserves first-arriving bytes in partial overlaps and notifies bounded gaps' do
    stream = Redhound::Analysis::TcpStream.new(max_bytes: 256)
    stream.push(100, ''.b, syn: true)
    expect(stream.push(105, 'EFGH')).to eq([])
    expect(stream.push(101, 'abcdef')).to eq(['abcd', 'EFGH'])
    expect(stream.diagnostics).to include(:overlap_mismatch)
    stream.push(120, 'later')
    expect(stream.flush_gap).to eq(['later'])
    expect(stream.diagnostics).to include(:reassembly_gap)
    expect(stream.bytesize).to be <= 256
  end

  it 'attaches split HTTP, TLS, and DNS PDUs to their completing frames' do
    messages = [["GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", 80, 'http.host'],
                [tls_record(tls_hello), 443, 'tls.handshake.extensions_server_name'],
                [[dns.bytesize].pack('n') + dns, 53, 'dns.qry.name']]
    messages.each do |message, port, field|
      session = Redhound::Analysis::Session.new
      session.update(packet(seq: 99, flags: 2, port: port))
      split = port == 53 ? 1 : message.bytesize / 3
      first = packet(message.byteslice(0, split), port: port, number: 2)
      middle = packet(message.byteslice(split, split), seq: 100 + split, port: port, number: 3)
      last = packet(message.byteslice(split * 2..), seq: 100 + split * 2, port: port, number: 4)
      [first, middle, last].each { |frame| session.update(frame) }
      expect(last[field]).to eq('example.test')
      expect(last.layers.last.field_value('tcp.reassembled_from')).to eq([2, 3, 4])
      session.finish(StringIO.new, StringIO.new)
    end
  end

  it 'marks duplicate ACKs, zero windows and initial RTT while retaining absolute sequences' do
    session = Redhound::Analysis::Session.new
    session.update(packet(seq: 100, flags: 2, timestamp_ns: 1_000_000))
    session.update(packet(seq: 500, ack: 101, flags: 0x12, reverse: true, timestamp_ns: 3_000_000))
    ack = packet(seq: 101, ack: 501, flags: 0x10, timestamp_ns: 5_000_000)
    session.update(ack)
    expect(ack['tcp.analysis.initial_rtt']).to eq(0.004)
    dup = packet(seq: 101, ack: 501, flags: 0x10, timestamp_ns: 6_000_000)
    session.update(dup)
    expect(dup['tcp.analysis.duplicate_ack']).to eq(true)
    zero = packet(seq: 101, ack: 501, flags: 0x10, window: 0, timestamp_ns: 7_000_000)
    session.update(zero)
    expect(zero['tcp.analysis.zero_window']).to eq(true)
    expect(zero['tcp.analysis.duplicate_ack']).to be_nil
    session.finish(StringIO.new, StringIO.new)
  end

  it 'computes interval, conversation, endpoint and hierarchy statistics without embedded traffic' do
    session = Redhound::Analysis::Session.new(stats: ['io,1', 'conv,tcp', 'endpoints,tcp', 'phs'])
    frames = [packet('a', number: 1), packet('b', reverse: true, seq: 900, number: 2, timestamp_ns: 1_000_000_000)]
    frames.each { |frame| session.update(frame) }
    results = session.statistics.map(&:to_h)
    expect(results[0][:rows].map { |row| row[:packets] }).to eq([1, 1])
    expect(results[1][:rows].first.values_at(:packets_ab, :packets_ba)).to eq([1, 1])
    expect(results[1][:rows].first.values_at(:bytes_ab, :bytes_ba)).to eq(frames.map(&:original_length))
    expect(results[2][:rows].map { |row| row[:packets_tx] }).to eq([1, 1])
    expect(results[3][:rows].find { |row| row[:path] == [:eth, :ipv4, :tcp] }[:packets]).to eq(2)
    session.finish(StringIO.new, StringIO.new)
  end

  it 'sanitizes ASCII follow output but leaves raw binary bytes intact' do
    %w[ascii hex raw].each do |format|
      session = Redhound::Analysis::Session.new(follow: "tcp,#{format},0")
      session.update(packet("a\e\x00\xff".b))
      out = StringIO.new(''.b)
      session.finish(out, StringIO.new)
      expect(out.string).not_to include("\e") unless format == 'raw'
      expect(out.string).to include('61 1b 00 ff') if format == 'hex'
      expect(out.string).to eq("a\e\x00\xff".b) if format == 'raw'
    end
  end

  it 'uses TCP stream numbers independently of UDP flows and restarts a reused connection' do
    session = Redhound::Analysis::Session.new(follow: 'tcp,raw,0')
    session.update(Redhound::Packet.new(ether(ipv4(udp('other', dport: 9999)))))
    frame = packet('first', seq: 1, flags: 0x18)
    session.update(frame)
    expect(frame['tcp.stream']).to eq(0)
    session.update(packet(seq: 6, flags: 4, number: 3))
    replacement = packet(seq: 1000, flags: 2, number: 4)
    session.update(replacement)
    expect(replacement['tcp.stream']).to eq(1)
    out = StringIO.new(''.b)
    session.finish(out, StringIO.new)
    expect(out.string).to eq('first')
  end

  it 'does not manufacture embedded ICMP flows or TCP statistics' do
    session = Redhound::Analysis::Session.new(stats: ['conv,tcp', 'conv,ip', 'phs'])
    inner = ipv4(tcp('payload', flags: 0x18), proto: 6)
    frame = Redhound::Packet.new(ether(ipv4([3, 3, 0, 0].pack('CCnN') + inner, proto: 1)))
    session.update(frame)
    expect(session.flows.size).to eq(1)
    expect(session.statistics.first.to_h[:rows]).to eq([])
    expect(session.statistics[1].to_h[:rows].size).to eq(1)
    expect(session.statistics.last.to_h[:rows].map { |row| row[:path] }).not_to include([:eth, :ipv4, :icmp, :ipv4])
    session.finish(StringIO.new, StringIO.new)
  end

  it 'bounds combined state, expires IP holes and keeps duplicate fragment metadata bounded' do
    session = Redhound::Analysis::Session.new(max_state_bytes: 2048, max_flows: 10, stats: ['conv,tcp'])
    30.times { |number| session.update(packet('x', port: 90 + number, number: number + 1)) }
    expect(session.bytesize).to be <= 2048
    expect(session.flows.evicted).to be > 0
    reassembler = Redhound::Analysis::IpReassembler.new(max_bytes: 1024)
    head = fragment(udp('abcdefgh'), offset: 0, more: true)
    reassembler.update(head)
    retained = reassembler.bytesize
    200.times { |number| reassembler.update(fragment(udp('abcdefgh'), offset: 0, more: true, number: number + 2)) }
    expect(reassembler.bytesize).to eq(retained)
    reassembler.expire(30_000_000_000)
    expect(reassembler.size).to eq(0)
    expect(reassembler.expired).to eq(1)
    session.finish(StringIO.new, StringIO.new)
  end

  it 'frames pipelined HTTP, close-delimited responses, and a handshake spanning TLS records' do
    session = Redhound::Analysis::Session.new
    session.update(packet(seq: 99, flags: 2))
    bytes = "GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\nGET /thr"
    first = packet(bytes, number: 2)
    session.update(first)
    expect(first.layers_of(:http).map { |layer| layer.field_value('http.request.uri') }).to eq(['/one', '/two'])
    last = packet("ee HTTP/1.1\r\n\r\n", seq: 100 + bytes.bytesize, number: 3)
    session.update(last)
    expect(last['http.request.uri']).to eq('/three')
    response = "HTTP/1.1 200 OK\r\n\r\nbody"
    session.update(packet(response, seq: 500, reverse: true, number: 4))
    fin = packet(seq: 500 + response.bytesize, flags: 0x11, reverse: true, number: 5)
    session.update(fin)
    expect(fin['http.file_data']).to eq('body')
    hello = tls_hello
    tls = Redhound::Analysis::Session.new
    tls.update(packet(seq: 99, flags: 2, port: 443))
    left = tls_record(hello.byteslice(0, 20))
    tls.update(packet(left, port: 443, number: 2))
    right = packet(tls_record(hello.byteslice(20..)), seq: 100 + left.bytesize, port: 443, number: 3)
    tls.update(right)
    expect(right['tls.handshake.extensions_server_name']).to eq('example.test')
    [session, tls].each { |item| item.finish(StringIO.new, StringIO.new) }
  end

  it 'skips unfillable holes on RST and closes after both FINs' do
    session = Redhound::Analysis::Session.new(follow: 'tcp,raw,0', protocol_streams: false)
    session.update(packet(seq: 99, flags: 2))
    session.update(packet('tail', seq: 150, number: 2))
    rst = packet(seq: 100, flags: 4, number: 3)
    session.update(rst)
    expect(rst[:tcp].diagnostics.map(&:code)).to include(:reassembly_gap)
    out = StringIO.new(''.b)
    session.finish(out, StringIO.new)
    expect(out.string).to eq('tail')
    session = Redhound::Analysis::Session.new
    session.update(packet(seq: 100, flags: 1))
    session.update(packet(seq: 500, flags: 1, reverse: true))
    expect(session.flows.values.first.closed?).to eq(true)
    session.finish(StringIO.new, StringIO.new)
  end

  it 'validates reassembled and repeated field values against the fixed JSON schema' do
    schema = JSONSchemer.schema(JSON.parse(File.read(File.expand_path('../../docs/json-schema.json', __dir__))))
    session = Redhound::Analysis::Session.new
    session.update(packet(seq: 99, flags: 2))
    request = "GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"
    session.update(packet(request.byteslice(0, 20), number: 2))
    last = packet(request.byteslice(20..), seq: 120, number: 3)
    session.update(last)
    expect(last[:http].field_values('http.cookie')).to eq(['a=1', 'b=2'])
    bytes = udp('abc', dport: 9999)
    session.update(fragment(bytes.byteslice(0, 8), offset: 0, more: true, number: 4))
    fragmented = fragment(bytes.byteslice(8..), offset: 8, more: false, number: 5)
    session.update(fragmented)
    vlan = Redhound.dissect(ether([100, 0x8100, 200, 0x0800].pack('n4') + ipv4(udp('abc', dport: 9999)), type: 0x8100))
    [last, fragmented, vlan].each { |frame| expect(schema.validate(JSON.parse(JSON.generate(frame.to_h))).to_a).to eq([]) }
    session.finish(StringIO.new, StringIO.new)
  end

  it 'handles deterministic stream disorder and fragment mutations within configured state limits' do
    random = Random.new(7345)
    session = Redhound::Analysis::Session.new(max_state_bytes: 16_384, ip_bytes: 4096, tcp_bytes: 4096, stream_bytes: 512)
    1000.times do |index|
      bytes = random.bytes(random.rand(1..80))
      frame = if index % 4 == 0
                fragment(bytes.ljust((bytes.bytesize + 7) / 8 * 8, "\0"), offset: random.rand(8) * 8, more: index % 8 == 0, number: index + 1, ipv6: index % 8 == 4)
              else
                packet(bytes, seq: random.rand(0xffff_ffff), ack: random.rand(0xffff_ffff), flags: [0x18, 2, 1, 4].sample(random: random), reverse: index.odd?, number: index + 1)
              end
      expect { session.update(frame) }.not_to raise_error
      expect(session.bytesize).to be <= 16_384
    end
    session.finish(StringIO.new, StringIO.new)
  end

  it 'preserves TLS encryption state after ChangeCipherSpec across TCP segments' do
    session = Redhound::Analysis::Session.new
    session.update(packet(seq: 99, flags: 2, port: 443))
    ccs = tls_record("\1", type: 20)
    session.update(packet(ccs, port: 443, number: 2))
    ciphertext = "\1\xff\xff\xffciphertext".b
    encrypted = packet(tls_record(ciphertext, type: 22), port: 443, seq: 100 + ccs.bytesize, number: 3)
    session.update(encrypted)
    expect(encrypted['tls.app_data']).to eq(ciphertext)
    expect(encrypted['tls.handshake.type']).to be_nil
    session.finish(StringIO.new, StringIO.new)
  end

  it 'frames HEAD responses without a body and preserves pipelined GET framing' do
    session = Redhound::Analysis::Session.new
    requests = "HEAD / HTTP/1.1\r\nHost: example.test\r\n\r\nGET /next HTTP/1.1\r\nHost: example.test\r\n\r\n"
    session.update(packet(requests))
    informational = "HTTP/1.1 100 Continue\r\n\r\n"
    session.update(packet(informational, seq: 500, reverse: true, number: 2))
    responses = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    response = packet(responses, seq: 500 + informational.bytesize, reverse: true, number: 3)
    session.update(response)
    expect(response.layers_of(:http).map { |layer| layer.field_value('http.response.code') }).to eq([200, 200])
    expect(response.layers_of(:http).map { |layer| layer.field_value('http.file_data') }).to eq([nil, 'body'])
    expect(response.layers_of(:http).flat_map { |layer| layer.diagnostics.map(&:code) }).not_to include(:truncated)
    session.finish(StringIO.new, StringIO.new)
  end

  it 'tracks FIN holes, preserves later earlier data, and closes after both FINs' do
    session = Redhound::Analysis::Session.new(follow: 'tcp,raw,0')
    session.update(packet(seq: 99, flags: 2))
    pending = packet(seq: 150, flags: 0x11, number: 2)
    session.update(pending)
    expect(pending['tcp.analysis.lost_segment']).to eq(true)
    expect(session.flows.values.first.streams.first.pending?).to eq(true)
    session.update(packet('a' * 50, seq: 100, number: 3))
    peer = packet(seq: 500, flags: 0x11, reverse: true, number: 4)
    session.update(peer)
    expect(session.flows.values.first.closed?).to eq(true)
    output = StringIO.new(''.b)
    session.finish(output, StringIO.new)
    expect(output.string).to eq('a' * 50)

    session = Redhound::Analysis::Session.new
    session.update(packet(seq: 99, flags: 2))
    session.update(packet(seq: 150, flags: 0x11, number: 2))
    peer = packet(seq: 500, flags: 0x11, reverse: true, number: 3)
    session.update(peer)
    expect(session.flows.values.first.closed?).to eq(true)
    expect(peer[:tcp].diagnostics.map(&:code)).to include(:reassembly_gap)
    expect(peer[:tcp].diagnostics.find { |diagnostic| diagnostic.code == :reassembly_gap }.message).to include('50')
    session.finish(StringIO.new, StringIO.new)
  end

  it 'reassembles heuristic HTTP on a nonstandard TCP port' do
    session = Redhound::Analysis::Session.new
    session.update(packet(seq: 99, flags: 2, port: 9999))
    first = "GET / HTTP/1.1\r\nHost: "
    session.update(packet(first, port: 9999, number: 2))
    completing = packet("example.test\r\n\r\n", seq: 100 + first.bytesize, port: 9999, number: 3)
    session.update(completing)
    expect(completing['http.host']).to eq('example.test')
    expect(completing[:http].field_value('tcp.reassembled_from')).to eq([2, 3])
    session.finish(StringIO.new, StringIO.new)
  end

  it 'reports incomplete EOF PDUs and FIN gaps while releasing all buffered application and TCP bytes' do
    [false, true].each do |fin|
      session = Redhound::Analysis::Session.new
      session.update(packet(seq: 99, flags: 2))
      session.update(packet("GET / HTTP/1.1\r\nHost: unfinished", number: 2))
      session.update(packet(seq: 150, flags: 0x11, number: 3)) if fin
      flow = session.flows.values.first
      expect(flow.applications.compact.sum(&:bytesize)).to be > 0
      error = StringIO.new
      session.finish(StringIO.new, error)
      expect(error.string.include?('reassembly_gap')).to eq(fin)
      expect(error.string).to match(/stream 0.*truncated/)
      expect(flow.applications.compact.sum(&:bytesize)).to eq(0)
      expect(flow.streams.compact.sum(&:bytesize)).to eq(0)
      expect(session.bytesize).to eq(Redhound::Analysis::Flow::BASE_BYTES)
    end
  end

  it 'finalizes valid close-delimited HTTP at EOF without incomplete diagnostics' do
    session = Redhound::Analysis::Session.new
    session.update(packet("HTTP/1.1 200 OK\r\n\r\nbody", seq: 500, reverse: true))
    flow = session.flows.values.first
    layers = session.tcp_reassembler.finish_flow(flow)
    expect(layers.last.field_value('http.file_data')).to eq('body')
    expect(layers.flat_map { |layer| layer.diagnostics.map(&:code) }).to eq([])
    error = StringIO.new
    session.finish(StringIO.new, error)
    expect(error.string).to eq('')
    expect(flow.applications.compact.sum(&:bytesize)).to eq(0)
  end

  it 'bounds outstanding HTTP request methods and clears them at EOF' do
    session = Redhound::Analysis::Session.new(stream_bytes: 256)
    request = "HEAD / HTTP/1.1\r\n\r\n"
    100.times do |index|
      frame = packet(request, seq: 100 + index * request.bytesize, number: index + 1)
      session.update(frame)
      flow = session.flows.values.first
      expect(flow.http_methods.flatten.size).to be <= 16
      expect(frame[:http].diagnostics.map(&:code)).to include(:reassembly_gap) if index == 16
    end
    flow = session.flows.values.first
    session.finish(StringIO.new, StringIO.new)
    expect(flow.http_methods.flatten).to eq([])
  end
end
