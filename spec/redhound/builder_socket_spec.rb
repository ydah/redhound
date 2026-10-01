# frozen_string_literal: true

RSpec.describe Redhound::Builder::Socket do
  it 'closes the socket when binding fails' do
    stub_const('Socket::AF_PACKET', 17)
    socket = double('socket', setsockopt: nil)
    membership = double('membership', build: '', ifindex: 1)
    allow(Redhound::Builder::PacketMreq).to receive(:new).and_return(membership)
    allow(Socket).to receive(:new).and_return(socket)
    allow(socket).to receive(:bind).and_raise(Errno::ENODEV)
    expect(socket).to receive(:close)

    expect { described_class.build(ifname: 'lo') }.to raise_error(Errno::ENODEV)
  end
end
