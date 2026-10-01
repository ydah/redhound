# frozen_string_literal: true

RSpec.describe Redhound::Receiver do
  it 'saves a packet before analysis and closes both resources on failure' do
    source = double('source', next_packet: ['packet', Time.at(1)], close: nil)
    writer = double('writer', start: nil, stop: nil)
    allow(Redhound::Resolver).to receive(:resolve).and_return(source)
    allow(Redhound::Writer).to receive(:new).and_return(writer)
    expect(writer).to receive(:write).with(msg: 'packet', time: Time.at(1)).ordered
    expect(Redhound::Analyzer).to receive(:analyze).ordered.and_raise(RuntimeError, 'analysis failed')
    expect(writer).to receive(:stop)
    expect(source).to receive(:close)

    expect { described_class.run(ifname: 'lo', filename: 'capture.pcap') }
      .to raise_error(RuntimeError, 'analysis failed')
  end

  it 'closes the capture source when opening the output file fails' do
    source = double('source')
    allow(Redhound::Resolver).to receive(:resolve).and_return(source)
    allow(Redhound::Writer).to receive(:new).and_raise(Errno::EACCES)
    expect(source).to receive(:close)

    expect { described_class.run(ifname: 'lo', filename: 'capture.pcap') }
      .to raise_error(Errno::EACCES)
  end
end
