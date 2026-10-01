# frozen_string_literal: true

RSpec.describe Redhound::Analyzer do
  def analyze(frame) = described_class.analyze(msg: frame, count: 0)

  it 'does not crash on padded ARP (B-01) and prints dotted-decimal (B-08)' do
    expect { analyze(ether(arp, type: 0x0806)) }
      .to output(/ARP .*SPA: 192\.0\.2\.1 .*TPA: 192\.0\.2\.2/).to_stdout
  end

  it 'prints unpadded 42-byte ARP (B-08)' do
    expect { analyze(ether(arp, type: 0x0806, pad: false)) }.to output(/ARP HType/).to_stdout
  end

  it 'reports a short frame as malformed instead of raising (B-02)' do
    expect { analyze("\x01\x02\x03".b) }.to output(/Malformed/).to_stdout
  end

  it 'prints IPv4 version 4 (B-04)' do
    expect { analyze(ether(ipv4(udp('hi')))) }.to output(/IPv4 Ver: 4 IHL: 5/).to_stdout
  end

  it 'honors IPv4 options when locating UDP (B-05)' do
    frame = ether(ipv4(udp('hi', sport: 5353, dport: 53), options: "\x01\x01\x01\x00".b))
    expect { analyze(frame) }.to output(/UDP Src: 5353 Dst: 53/).to_stdout
  end

  it 'excludes ethernet padding from the UDP payload (B-14)' do
    expect { analyze(ether(ipv4(udp('hi')))) }.to output(/Payload: hi\n/).to_stdout
  end

  it 'decodes the IPv6 fixed header (B-06/B-07)' do
    frame = ether(ipv6(udp('x'), tclass: 0xab, flow: 0x12345), type: 0x86dd)
    expect { analyze(frame) }
      .to output(/IPv6 Ver: 6 Traffic Class: 171 Flow Label: 74565 .*Src: 2001:db8::1 Dst: 2001:db8::2/).to_stdout
  end

  it 'sanitizes control characters in payloads (B-10)' do
    frame = ether(ipv4(icmp_echo("\e[31mRED".b), proto: 1))
    expect { analyze(frame) }.to output(/Payload: \.\[31mRED/).to_stdout
  end
end
