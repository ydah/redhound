# frozen_string_literal: true

require_relative '../fixtures/generators/applications'

RSpec.describe 'application protocols' do
  include ApplicationFixtures

  def app_packet(bytes, tcp: false, port: 53)
    bytes = bytes.b
    transport = tcp ? self.tcp(bytes, dport: port, flags: 0x18) : udp(bytes, dport: port)
    Redhound::Packet.new(ether(ipv4(transport, proto: tcp ? 6 : 17)))
  end

  def codes(packet, protocol) = packet[protocol]&.diagnostics&.map(&:code) || []

  it 'decodes compressed DNS answers and TCP message length' do
    bytes = dns([dns_rr(1, ip4('192.0.2.10')), dns_rr(28, ip6('2001:db8::10'))])
    packet = app_packet(bytes)
    expect(packet['dns.qry.name']).to eq('example.test')
    expect(packet['dns.a']).to eq('192.0.2.10')
    expect(packet['dns.aaaa']).to eq('2001:db8::10')
    expect(app_packet([bytes.bytesize].pack('n') + bytes, tcp: true)['dns.length']).to eq(bytes.bytesize)
  end

  it 'decodes mDNS and LLMNR ports' do
    [5353, 5355].each do |port|
      expect(app_packet(dns, port: port)['dns.qry.name']).to eq('example.test')
    end
    packet = app_packet(dns(flags: 0x0500), port: 5355)
    expect(packet['dns.flags.conflict']).to eq(true)
    expect(packet['dns.flags.tentative']).to eq(true)
    expect(packet['dns.flags.authoritative']).to be_nil
  end

  it 'decodes name, mail, text, authority and service DNS records' do
    soa = dns_name('ns.example.test') + dns_name('hostmaster.example.test') + [42, 60, 30, 3600, 300].pack('N5')
    records = [dns_rr(5, dns_name('alias.example.test')), dns_rr(2, dns_name('ns.example.test')),
               dns_rr(12, dns_name('ptr.example.test')), dns_rr(15, [10].pack('n') + dns_name('mail.example.test')),
               dns_rr(16, "\3abc\3def"), dns_rr(6, soa),
               dns_rr(33, [1, 2, 443].pack('n3') + dns_name('service.example.test'))]
    packet = app_packet(dns(records))
    expect(packet['dns.cname']).to eq('alias.example.test')
    expect(packet['dns.ns']).to eq('ns.example.test')
    expect(packet['dns.ptr.domain_name']).to eq('ptr.example.test')
    expect(packet['dns.mx.mail_exchange']).to eq('mail.example.test')
    expect(packet[:dns].fields.select { |f| f.name == 'dns.txt' }.map(&:value)).to eq(%w[abc def])
    expect(packet['dns.soa.serial_number']).to eq(42)
    expect(packet['dns.srv.port']).to eq(443)
  end

  it 'decodes HTTPS service parameters and EDNS' do
    svc = [1].pack('n') + dns_name('svc.example.test') + [1, 3, 2].pack('nnC') + 'h2' + [3, 2, 443].pack('n3')
    opt = dns_rr(41, [10, 8].pack('nn') + '12345678', name: "\0", klass: 1232, ttl: 0x8000)
    packet = app_packet(dns([dns_rr(65, svc)], additional: [opt]))
    expect(packet['dns.svcb.targetname']).to eq('svc.example.test')
    expect(packet['dns.svcb.svcparam.alpn']).to eq('h2')
    expect(packet['dns.svcb.svcparam.port']).to eq(443)
    expect(packet['dns.rr.udp_payload_size']).to eq(1232)
    expect(packet['dns.resp.z.do']).to eq(true)
    expect(packet['dns.opt.cookie.client']).to eq('12345678')
  end

  it 'rejects DNS pointer loops, forward pointers and overlong names' do
    header = [1, 0, 1, 0, 0, 0].pack('n6')
    ["\xc0\x0c".b, "\xc0\x0e".b, "\1a\xc0\x0c".b, ("\x3f" + 'a' * 63) * 4 + "\0"].each do |name|
      expect(codes(app_packet(header + name + [1, 1].pack('n2')), :dns)).to include(:malformed)
    end
    longest = (['a' * 63] * 3 + ['a' * 61]).join('.')
    expect(app_packet(dns(question: longest))['dns.qry.name']).to eq(longest)
    pointers, target = "\0".b, 0
    129.times do
      offset = pointers.bytesize
      pointers << [0xc000 | target].pack('n')
      target = offset
    end
    expect { Redhound::Protocols::Dns.new.read_name(Redhound::Cursor.new(pointers), target) }
      .to raise_error(Redhound::Protocols::Dns::Malformed, /128 jumps/)
  end

  it 'preserves DNS header fields on a truncated question or TCP message' do
    packet = app_packet(dns.byteslice(0, 14))
    expect(packet['dns.id']).to eq(0x1234)
    expect(codes(packet, :dns)).to include(:truncated)
    expect(codes(app_packet([200].pack('n') + dns, tcp: true), :dns)).to include(:truncated)
  end

  it 'decodes DHCP fixed header and required options' do
    options = [53, 1, 2, 50, 4].pack('C*') + ip4('192.0.2.20') + [51, 4, 3600].pack('CCN') +
              [54, 4].pack('CC') + ip4('192.0.2.1') + [55, 3, 1, 3, 6, 61, 7, 1].pack('C*') +
              mac('02:00:00:00:00:01') + [1, 4].pack('CC') + ip4('255.255.255.0') +
              [3, 4].pack('CC') + ip4('192.0.2.1') + [6, 8].pack('CC') + ip4('192.0.2.53') +
              ip4('192.0.2.54') + [12, 4].pack('CC') + 'host' + "\xff".b
    packet = app_packet(dhcp(options), port: 67)
    expect(packet['dhcp.type']).to eq(1)
    expect(packet['dhcp.ip.your']).to eq('192.0.2.10')
    expect(packet['dhcp.hw.mac_addr']).to eq('02:00:00:00:00:01')
    expect(packet['dhcp.option.dhcp']).to eq(2)
    expect(packet['dhcp.option.requested_ip_address']).to eq('192.0.2.20')
    expect(packet['dhcp.option.ip_address_lease_time']).to eq(3600)
    expect(packet['dhcp.option.hostname']).to eq('host')
    expect(packet[:dhcp].fields.select { |f| f.name == 'dhcp.option.domain_name_server' }.map(&:value)).to eq(%w[192.0.2.53 192.0.2.54])
  end

  it 'supports DHCP option overload and rejects malformed option lengths' do
    packet = app_packet(dhcp([52, 1, 1, 255].pack('C*'), file: [12, 4].pack('CC') + 'host' + "\xff"), port: 68)
    expect(packet['dhcp.option.hostname']).to eq('host')
    expect(codes(app_packet(dhcp([53, 2, 1, 2, 255].pack('C*')), port: 67), :dhcp)).to include(:bad_length)
    expect(codes(app_packet(dhcp([12, 20, 1].pack('C*')), port: 67), :dhcp)).to include(:truncated)
  end

  it 'decodes NTP flags and keeps timestamp precision as an integer' do
    packet = app_packet(ntp, port: 123)
    expect(packet['ntp.flags.vn']).to eq(4)
    expect(packet['ntp.flags.mode']).to eq(4)
    expect(packet['ntp.stratum']).to eq(2)
    expect(packet['ntp.xmt']).to eq((3_900_000_000 << 32) | (1 << 31))
  end

  it 'decodes HTTP request and response headers and marks incomplete messages' do
    packet = app_packet("GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\nUser-Agent: test\r\n\r\n", tcp: true, port: 80)
    expect(packet['http.request.method']).to eq('GET')
    expect(packet['http.request.uri']).to eq('/path?q=1')
    expect(packet['http.host']).to eq('example.test')
    response = app_packet("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc", tcp: true, port: 8080)
    expect(response['http.response.code']).to eq(200)
    expect(response['http.content_length']).to eq(4)
    expect(codes(response, :http)).to include(:truncated)
    expect(codes(app_packet("GET / HTTP/1.1\r\nHost: example", tcp: true, port: 8000), :http)).to include(:truncated)
  end

  it 'decodes chunked HTTP bodies and rejects conflicting framing' do
    bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    expect(app_packet(bytes, tcp: true, port: 80)['http.file_data']).to eq('abc')
    conflict = "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"
    expect(codes(app_packet(conflict, tcp: true, port: 80), :http)).to include(:malformed)
  end

  it 'decodes TLS ClientHello and ServerHello extensions' do
    packet = app_packet(tls_record(tls_hello), tcp: true, port: 443)
    expect(packet['tls.record.content_type']).to eq(22)
    expect(packet['tls.handshake.type']).to eq(1)
    expect(packet['tls.handshake.ciphersuite']).to eq(0x1301)
    expect(packet['tls.handshake.extensions_server_name']).to eq('example.test')
    expect(packet['tls.handshake.extensions_alpn_str']).to eq('h2')
    expect(packet['tls.handshake.extensions.supported_version']).to eq(0x0304)
    server = app_packet(tls_record(tls_hello(server: true)), tcp: true, port: 443)
    expect(server['tls.handshake.type']).to eq(2)
    expect(server['tls.handshake.extensions.supported_version']).to eq(0x0304)
  end

  it 'handles multiple TLS records and split handshakes in one TCP segment' do
    hello = tls_hello
    bytes = tls_record(hello.byteslice(0, 20)) + tls_record(hello.byteslice(20..)) + tls_record('encrypted', type: 23)
    packet = app_packet(bytes, tcp: true, port: 443)
    expect(packet['tls.handshake.extensions_server_name']).to eq('example.test')
    expect(packet[:tls].fields.count { |f| f.name == 'tls.record.content_type' }).to eq(3)
  end

  it 'diagnoses partial TLS records and invalid extension lengths without exceptions' do
    expect(codes(app_packet(tls_record(tls_hello).byteslice(0, 30), tcp: true, port: 443), :tls)).to include(:truncated)
    extension = tls_extension(43, [3, 0x0304].pack('Cn'))
    expect(codes(app_packet(tls_record(tls_hello(extensions: extension)), tcp: true, port: 443), :tls)).to include(:bad_length)
  end

  it 'escapes DNS, HTTP and TLS text before rendering summaries' do
    packets = [app_packet(dns(question: "bad\e[31m.test")),
               app_packet("GET /bad\e[31m HTTP/1.1\r\n\r\n", tcp: true, port: 80),
               app_packet(tls_record(tls_hello(sni: "bad\e[31m.test")), tcp: true, port: 443)]
    packets.each do |packet|
      layer = packet.layers.last
      expect(%i[dns http tls]).to include(layer.protocol)
      klass = Redhound::Registry.default.protocols.fetch(layer.protocol)
      expect(klass.new.summary(layer)).not_to include("\e")
    end
  end

  it 'parses all truncation points and deterministic mutations without parser bugs' do
    rng = Random.new(42)
    messages = [[dns([dns_rr(1, ip4('192.0.2.10'))]), false, 53], [dhcp, false, 67], [ntp, false, 123],
                ["GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", true, 80], [tls_record(tls_hello), true, 443]]
    messages.each do |bytes, tcp, port|
      (0..bytes.bytesize).each do |length|
        packet = app_packet(bytes.byteslice(0, length), tcp: tcp, port: port)
        expect(packet.layers.flat_map { |layer| layer.diagnostics.map(&:code) }).not_to include(:dissector_bug)
      end
      1000.times do
        mutated = bytes.dup
        rng.rand(1..4).times do
          pos = rng.rand(mutated.bytesize)
          mutated.setbyte(pos, rng.rand(256))
        end
        packet = app_packet(mutated, tcp: tcp, port: port)
        expect(packet.layers.flat_map { |layer| layer.diagnostics.map(&:code) }).not_to include(:dissector_bug)
      end
    end
  end

  it 'retains repeated TCP DNS messages and rejects record-local length errors' do
    first, second = dns(question: 'one.test'), dns(question: 'two.test')
    packet = app_packet([first.bytesize].pack('n') + first + [second.bytesize].pack('n') + second, tcp: true)
    expect(packet.field_values('dns.qry.name')).to eq(%w[one.test two.test])
    expect(codes(app_packet(dns([dns_rr(1, 'abc')])), :dns)).to include(:bad_length)
    [dns_rr(5, dns_name('alias.test') + 'extra'), dns_rr(16, "\4abc"), dns_rr(15, "\0"),
     dns_rr(6, dns_name('ns.test') + dns_name('host.test')), dns_rr(65, [1].pack('n') + "\xc0\x0c".b),
     dns_rr(41, [1, 100].pack('nn'), name: "\0"), dns_rr(41, [10, 1, 0].pack('nnC'), name: "\0")].each do |rr|
      expect(codes(app_packet(dns([rr])), :dns)).to include(:malformed)
    end
    expect(app_packet(dns([dns_rr(99, 'unknown')]))['dns.data']).to eq('unknown')
  end

  it 'decodes SVCB address hints and rejects invalid service parameters' do
    target = [1].pack('n') + dns_name('svc.test')
    params = [0, 4, 1, 3].pack('n4') + [1, 3, 2].pack('nnC') + 'h2' + [2, 0].pack('nn') +
             [3, 2, 443].pack('n3') + [4, 4].pack('nn') + ip4('192.0.2.1') +
             [6, 16].pack('nn') + ip6('2001:db8::1') + [7, 4].pack('nn') + '/dns'
    packet = app_packet(dns([dns_rr(64, target + params)]))
    expect(packet['dns.svcb.svcparam.ipv4hint.ip']).to eq('192.0.2.1')
    expect(packet['dns.svcb.svcparam.ipv6hint.ip']).to eq('2001:db8::1')
    expect(packet['dns.svcb.svcparam.dohpath']).to eq('/dns')
    invalid = ['x', [1, 100].pack('nn'), [3, 1, 0].pack('nnC'), [1, 1, 0].pack('nnC'),
               [2, 1, 0].pack('nnC'), [3, 2, 443, 1, 0].pack('n5')]
    invalid.each { |params| expect(codes(app_packet(dns([dns_rr(65, target + params)])), :dns)).to include(:malformed) }
  end

  it 'parses BOOTP, concatenated DHCP options and overloaded server names' do
    packet = app_packet(dhcp([0, 12, 2].pack('C*') + 'ho' + [12, 2].pack('C*') + 'st' + "\xff".b), port: 67)
    expect(packet['dhcp.option.hostname']).to eq('host')
    packet = app_packet(dhcp([52, 1, 2, 255].pack('C*'), sname: [12, 4].pack('CC') + 'host' + "\xff".b), port: 67)
    expect(packet['dhcp.option.hostname']).to eq('host')
    expect(app_packet(dhcp.byteslice(0, 236), port: 67)['dhcp.type']).to eq(1)
    vendor = dhcp.dup
    vendor[236, 4] = 'boot'
    expect(app_packet(vendor, port: 67)['dhcp.vendor']).to start_with('boot')
    malformed = dhcp.dup
    malformed.setbyte(2, 17)
    expect(codes(app_packet(malformed, port: 67), :dhcp)).to include(:bad_length)
    [[50, 3, 1, 2, 3, 255], [51, 1, 0, 255], [52, 1, 4, 255], [61, 1, 1, 255]].each do |option|
      expect(codes(app_packet(dhcp(option.pack('C*')), port: 67), :dhcp)).to include(:bad_length)
    end
  end

  it 'handles NTP extensions and rejects an invalid mode' do
    expect(app_packet(ntp + 'authentication', port: 123)['ntp.extension']).to eq('authentication')
    invalid = ntp.dup
    invalid.setbyte(0, 0x20)
    expect(codes(app_packet(invalid, port: 123), :ntp)).to include(:malformed)
    expect(app_packet(ntp, port: 123)['ntp.precision']).to eq(-6)
  end

  it 'handles HTTP pipelining, close framing and bodyless responses' do
    request = "GET / HTTP/1.1\r\nX-Test: value\r\n\r\n"
    expect(app_packet(request * 2, tcp: true, port: 80).field_values('http.request.method')).to eq(%w[GET GET])
    response = "HTTP/1.1 204 No Content\r\n\r\nHTTP/1.0 200 OK\r\n\r\nabc"
    packet = app_packet(response, tcp: true, port: 80)
    expect(packet.field_values('http.response.code')).to eq([204, 200])
    expect(packet['http.file_data']).to eq('abc')
    response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\ncompressed"
    expect(app_packet(response, tcp: true, port: 80)['http.file_data']).to eq('compressed')
    expect(app_packet("POST / HTTP/1.1\r\nContent-Length: 3, 3\r\n\r\nabc", tcp: true, port: 80)['http.file_data']).to eq('abc')
  end

  it 'diagnoses HTTP invalid start lines, headers and chunk framing' do
    invalid = ["WRONG\r\n\r\n", "HTTP/1.1 20 OK\r\n\r\n", "GET / HTTP/1.1\r\nBad Header: x\r\n\r\n",
               "GET / HTTP/1.1\r\nHost: bad\evalue\r\n\r\n", "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
               "POST / HTTP/1.1\r\nContent-Length: x\r\n\r\n", "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n"]
    invalid.each { |bytes| expect(codes(app_packet(bytes, tcp: true, port: 80), :http)).to include(:malformed) }
    header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    ["nope\r\n", "3\r\nabc!!"].each do |body|
      expect(codes(app_packet(header + body, tcp: true, port: 80), :http)).to include(:malformed)
    end
    ["3", "3\r\nab", "0\r\nX-Trailer: x"].each do |body|
      expect(codes(app_packet(header + body, tcp: true, port: 80), :http)).to include(:truncated)
    end
    expect(app_packet(header + "1\r\na\r\n0\r\nX-Trailer: x\r\n\r\n", tcp: true, port: 80)['http.chunked.trailer']).to eq('X-Trailer: x')
  end

  it 'preserves a complete TLS hello before a partial record and parses cleartext alerts' do
    bytes = tls_record(tls_hello) + [23, 0x0303, 10].pack('Cnn') + 'ab'
    packet = app_packet(bytes, tcp: true, port: 443)
    expect(packet['tls.handshake.extensions_server_name']).to eq('example.test')
    expect(codes(packet, :tls)).to include(:truncated)
    expect(app_packet(tls_record([2, 40].pack('CC'), type: 21), tcp: true, port: 443)['tls.alert_message.desc']).to eq(40)
    expect(app_packet(tls_record("\1", type: 20) + tls_record('opaque'), tcp: true, port: 443)['tls.app_data']).to eq('opaque')
    expect(codes(app_packet([21, 0x0303, 2, 1].pack('CnnC'), tcp: true, port: 443), :tls)).to include(:truncated)
  end

  it 'rejects inconsistent TLS hello and extension vectors' do
    bodies = [tls_record("\0", type: 20), tls_record('x', type: 21), [99, 0x0303, 0].pack('Cnn'),
              tls_record([1, 0, 0, 2, 3, 3].pack('C*'))]
    extensions = [tls_extension(0, [3, 0, 0].pack('nCn')), tls_extension(16, [1, 0].pack('nC')),
                  tls_extension(43, [2, 0x0304].pack('Cn')) * 2, tls_extension(0, "\0")]
    extensions.each { |ext| bodies << tls_record(tls_hello(extensions: ext)) }
    short_hello = tls_hello.dup
    short_hello.setbyte(38, 33)
    bodies << tls_record(short_hello)
    bodies.each { |bytes| expect(codes(app_packet(bytes, tcp: true, port: 443), :tls)).to include(:bad_length) }
  end
end
