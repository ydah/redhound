# frozen_string_literal: true
require 'spec_helper'
require 'redhound/filter'

RSpec.describe Redhound::Filter::Program do
  PacketBytes = Struct.new(:data, :original_length, :linktype, :meta)
  def packet(data, length: data.bytesize, meta: {})
    PacketBytes.new(data.b, length, 1, meta)
  end

  it 'executes tcpdump classic BPF, refuses truncated loads, and packs native structs' do
    instructions = [[0x28, 0, 0, 12], [0x15, 0, 8, 0x800], [0x30, 0, 0, 23],
                    [0x15, 0, 6, 17], [0x28, 0, 0, 20], [0x45, 4, 0, 0x1fff],
                    [0xb1, 0, 0, 14], [0x48, 0, 0, 16], [0x15, 0, 1, 53],
                    [0x06, 0, 0, 262144], [0x06, 0, 0, 0]]
    program = described_class.new(instructions, linktype: 1)
    expect(program.match?(packet(ether(ipv4(udp('x'.b)))))).to be true
    expect(program.match?(packet(ether(ipv4(udp('x'.b, dport: 80)))))).to be false
    expect(program.match?(packet("\0" * 13))).to be false
    expect(program.packed).to eq(instructions.map { |i| i.pack('SCCL') }.join)
    expect(program.disassemble(format: :ruby)).to include('0x0028')
    expect(program.disassemble(format: :decimal).lines.first.strip).to eq('11')
    expect(program.disassemble).to include('ldh', 'jeq', 'ret')
  end

  it 'rejects unsafe bytecode before execution' do
    bad = [[nil], [[0x28, 0, 0, 0xfffff030], [6, 0, 0, 0]], [], [[0xffff, 0, 0, 0], [6, 0, 0, 0]], [[5, 0, 0, 20], [6, 0, 0, 0]],
           [[0x60, 0, 0, 16], [6, 0, 0, 0]], [[0x60, 0, 0, 0], [6, 0, 0, 0]],
           [[0x34, 0, 0, 0], [6, 0, 0, 0]], [[0x94, 0, 0, 0], [6, 0, 0, 0]],
           [[0x00, 0, 0, 1]], [[0x15, 256, 0, 1], [6, 0, 0, 0]],
           [[0x64, 0, 0, 32], [6, 0, 0, 0]]]
    bad.each { |insns| expect { described_class.new(insns) }.to raise_error(Redhound::FilterError) }
    expect { described_class.new(Array.new(4097) { [6, 0, 0, 0] }) }.to raise_error(Redhound::FilterTooLarge)
  end

  it 'implements unsigned arithmetic, scratch memory, original length and division rejection' do
    program = described_class.new([[0x00, 0, 0, 0xffffffff], [0x04, 0, 0, 2], [0x02, 0, 0, 0],
                                   [0x01, 0, 0, 3], [0x0c, 0, 0, 0], [0x60, 0, 0, 0], [0x16, 0, 0, 0]])
    expect(program.evaluate(packet(''))).to eq(1)
    expect(described_class.new([[0x80, 0, 0, 0], [0x16, 0, 0, 0]]).evaluate(packet('', length: 300))).to eq(300)
    expect(described_class.new([[0x01, 0, 0, 0], [0x3c, 0, 0, 0], [0x16, 0, 0, 0]]).evaluate(packet(''))).to eq(0)
  end

  it 'reads stripped VLAN tags through Linux ancillary loads' do
    program = described_class.new([[0x20, 0, 0, 0xfffff030], [0x16, 0, 0, 0]])
    expect(program.evaluate(packet('', meta: { vlan_tci: 0 }))).to eq(1)
    expect(program.evaluate(packet(''))).to eq(0)
  end
end
