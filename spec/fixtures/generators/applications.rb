# frozen_string_literal: true

# Deterministic wire messages; packet envelopes live in PacketFactory.
module ApplicationFixtures
  module_function

  def dns_name(name)
    name.split('.').map { |label| [label.bytesize].pack('C') + label.b }.join.b + "\0"
  end

  def dns_rr(type, data, name: "\xc0\x0c".b, klass: 1, ttl: 60)
    name + [type, klass, ttl, data.bytesize].pack('nnNn') + data
  end

  def dns(records = [], question: 'example.test', type: 1, flags: 0x8180, additional: [])
    [0x1234, flags, 1, records.length, 0, additional.length].pack('n6') +
      dns_name(question) + [type, 1].pack('n2') + records.join + additional.join
  end

  def dhcp(options = [53, 1, 1, 255].pack('C*'), file: ''.b, sname: ''.b)
    [1, 1, 6, 0, 0x12345678, 0, 0x8000].pack('C4Nnn') + "\0" * 4 +
      [0xc000020a, 0, 0].pack('N3') + [2, 0, 0, 0, 0, 1].pack('C6').ljust(16, "\0") +
      sname.b.ljust(64, "\0") + file.b.ljust(128, "\0") + [0x63825363].pack('N') + options.b
  end

  def ntp
    [0x24, 2, 6, 0xfa, 0, 0, 0].pack('C4N3') + [0, 0, 0, (3_900_000_000 << 32) | (1 << 31)].pack('Q>4')
  end

  def tls_extension(type, data) = [type, data.bytesize].pack('n2') + data

  def tls_record(data, type: 22) = [type, 0x0303, data.bytesize].pack('Cnn') + data

  def tls_hello(server: false, sni: 'example.test', extensions: nil)
    sni_value = [sni.bytesize + 3, 0, sni.bytesize].pack('nCn') + sni.b
    alpn = [3, 2].pack('nC') + 'h2'
    versions = server ? [0x0304].pack('n') : [4, 0x0304, 0x0303].pack('Cnn')
    extensions ||= tls_extension(0, sni_value) + tls_extension(16, alpn) + tls_extension(43, versions)
    body = [0x0303].pack('n') + "\0" * 32 + "\0" +
           (server ? [0x1301, 0].pack('nC') : [2, 0x1301, 1, 0].pack('nnCC')) +
           [extensions.bytesize].pack('n') + extensions
    [server ? 2 : 1].pack('C') + [body.bytesize].pack('N').byteslice(1, 3) + body
  end

  def sample_messages
    soa = dns_name('ns.example.test') + dns_name('hostmaster.example.test') + [42, 60, 30, 3600, 300].pack('N5')
    records = [dns_rr(1, ip4('192.0.2.10')), dns_rr(28, ip6('2001:db8::10')),
               dns_rr(5, dns_name('alias.example.test')), dns_rr(15, [10].pack('n') + dns_name('mail.example.test')),
               dns_rr(16, "\3abc\3def"), dns_rr(6, soa), dns_rr(33, [1, 2, 443].pack('n3') + dns_name('service.example.test'))]
    svc = [1].pack('n') + dns_name('svc.example.test') + [1, 3, 2].pack('nnC') + 'h2' + [3, 2, 443].pack('n3')
    opt = dns_rr(41, ''.b, name: "\0", klass: 1232, ttl: 0x8000)
    {
      dns: [dns(records), false, 53],
      https_dns: [dns([dns_rr(65, svc)], additional: [opt]), false, 53],
      mdns: [dns([], flags: 0), false, 5353],
      llmnr: [dns([], flags: 0), false, 5355],
      dhcp: [dhcp([53, 1, 1, 12, 4].pack('C*') + 'host' + "\xff".b), false, 67],
      ntp: [ntp, false, 123],
      http_request: ["GET /test HTTP/1.1\r\nHost: example.test\r\n\r\n", true, 80],
      http_response: ["HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", true, 80],
      tls_client: [tls_record(tls_hello), true, 443],
      tls_server: [tls_record(tls_hello(server: true, extensions: tls_extension(43, [0x0304].pack('n')))), true, 443]
    }
  end
end

if $PROGRAM_NAME == __FILE__
  require_relative '../../../lib/redhound'
  require_relative '../../support/packet_factory'
  factory = Object.new.extend(PacketFactory).extend(ApplicationFixtures)
  directory = File.expand_path('../pcap', __dir__)
  Dir.mkdir(directory) unless Dir.exist?(directory)
  writer = Redhound::File::PcapWriter.new(File.join(directory, 'applications.pcap'))
  factory.instance_eval do
    sample_messages.values.each_with_index do |(bytes, tcp, port), i|
      transport = tcp ? self.tcp(bytes, dport: port, flags: 0x18, seq: 1, sport: 40_000 + i) : udp(bytes, dport: port, sport: 40_000 + i)
      writer.write(Redhound::Packet.new(ether(ipv4(transport, proto: tcp ? 6 : 17)),
                                      timestamp_ns: 1_700_000_000_000_000_000 + i * 1_000_000, number: i + 1))
    end
  end
  writer.close
end
