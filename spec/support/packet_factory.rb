# frozen_string_literal: true

require 'ipaddr'

# テスト用にパケットのバイト列を組み立てるヘルパ
module PacketFactory
  module_function

  def checksum(bytes)
    sum = bytes.unpack('n*').sum
    sum += bytes.getbyte(-1) << 8 if bytes.bytesize.odd?
    sum = (sum & 0xffff) + (sum >> 16) while sum > 0xffff
    ~sum & 0xffff
  end

  def mac(str) = str.split(':').map { |h| h.to_i(16) }.pack('C6')
  def ip4(str) = IPAddr.new(str).hton
  def ip6(str) = IPAddr.new(str).hton

  def ether(payload, dst: 'ff:ff:ff:ff:ff:ff', src: '02:00:00:00:00:01', type: 0x0800, pad: true)
    frame = mac(dst) + mac(src) + [type].pack('n') + payload
    pad && frame.bytesize < 60 ? frame.ljust(60, "\0") : frame
  end

  def ipv4(payload, src: '192.0.2.1', dst: '192.0.2.2', proto: 17, ttl: 64, id: 1, options: ''.b)
    ihl = 5 + (options.bytesize / 4)
    hdr = [0x40 | ihl, 0, (ihl * 4) + payload.bytesize, id, 0x4000, ttl, proto, 0].pack('CCnnnCCn') +
          ip4(src) + ip4(dst) + options
    hdr[10, 2] = [checksum(hdr)].pack('n')
    hdr + payload
  end

  def ipv6(payload, src: '2001:db8::1', dst: '2001:db8::2', next_header: 17, hop_limit: 64, tclass: 0, flow: 0)
    [(6 << 28) | (tclass << 20) | flow, payload.bytesize, next_header, hop_limit].pack('NnCC') +
      ip6(src) + ip6(dst) + payload
  end

  def udp(payload, sport: 12_345, dport: 53)
    [sport, dport, 8 + payload.bytesize, 0].pack('nnnn') + payload
  end

  def icmp_echo(payload = 'ping'.b, type: 8, id: 1, seq: 1)
    msg = [type, 0, 0, id, seq].pack('CCnnn') + payload
    msg[2, 2] = [checksum(msg)].pack('n')
    msg
  end

  def tcp(payload = ''.b, sport: 40_000, dport: 80, seq: 1, ack: 0, flags: 0x02, window: 64_240)
    [sport, dport, seq, ack, (5 << 12) | flags, window, 0, 0].pack('nnNNnnnn') + payload
  end

  def arp(oper: 1, sha: '02:00:00:00:00:01', spa: '192.0.2.1', tha: '00:00:00:00:00:00', tpa: '192.0.2.2')
    [1, 0x0800, 6, 4, oper].pack('nnCCn') + mac(sha) + ip4(spa) + mac(tha) + ip4(tpa)
  end
end
