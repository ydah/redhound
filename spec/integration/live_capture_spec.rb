# frozen_string_literal: true

require 'socket'
require 'tmpdir'

RSpec.describe 'live capture on lo', :live do
  def capture(seconds: 1.5, &traffic)
    Dir.mktmpdir do |dir|
      pcap = File.join(dir, 'out.pcap')
      exe = File.expand_path('../../exe/redhound', __dir__)
      pid = Process.spawn(RbConfig.ruby, exe, '-i', 'lo', '-w', pcap, out: File::NULL, err: File::NULL)
      sleep 1.0
      traffic.call
      sleep seconds - 1.0
      Process.kill(:TERM, pid)
      _, status = Process.wait2(pid)
      pid = nil
      expect(status.success?).to be(true)
      yield_records(File.binread(pcap))
    ensure
      if pid
        Process.kill(:TERM, pid) rescue Errno::ESRCH
        Process.wait(pid) rescue Errno::ECHILD
      end
    end
  end

  def yield_records(bin)
    records = []
    pos = 24
    while pos + 16 <= bin.bytesize
      sec, usec, caplen, = bin.unpack('VVVV', offset: pos)
      records << [sec, usec, bin.byteslice(pos + 16, caplen)]
      pos += 16 + caplen
    end
    records
  end

  it 'records each loopback packet once with a kernel timestamp (B-11, B-13)' do
    marker = "redhound-#{rand(1 << 32)}"
    sent_at = nil
    records = capture do
      sent_at = Time.now
      UDPSocket.open { |socket| socket.send(marker, 0, '127.0.0.1', 9) }
    end
    # ICMP port unreachable にも元の UDP が埋め込まれるため、IP プロトコル番号 17 に限定する
    hits = records.select { |_, _, data| data.getbyte(23) == 17 && data.include?(marker) }
    expect(hits.size).to eq(1)
    sec, usec, = hits.first
    expect(Time.at(sec, usec)).to be_within(0.5).of(sent_at)
  end
end
