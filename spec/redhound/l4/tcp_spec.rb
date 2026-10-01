# frozen_string_literal: true

RSpec.describe 'TCP capture display' do
  it 'prints ports, flags and payload length over IPv4' do
    frame = ether(ipv4(tcp('GET /'.b, flags: 0x18), proto: 6))
    expect { Redhound::Analyzer.analyze(msg: frame, count: 0) }
      .to output(/TCP Src: 40000 Dst: 80 Seq: 1 Ack: 0 Flags: \[ACK,PSH\] Win: 64240 Len: 5/).to_stdout
  end

  it 'works over IPv6' do
    frame = ether(ipv6(tcp(flags: 0x12), next_header: 6), type: 0x86dd)
    expect { Redhound::Analyzer.analyze(msg: frame, count: 0) }.to output(/Flags: \[ACK,SYN\]/).to_stdout
  end

  it 'reports a bogus data offset as malformed' do
    seg = tcp.dup
    seg.setbyte(12, 0x10) # data offset = 4 bytes
    expect { Redhound::Analyzer.analyze(msg: ether(ipv4(seg, proto: 6)), count: 0) }.to output(/Malformed/).to_stdout
  end
end
