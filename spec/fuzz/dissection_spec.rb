# frozen_string_literal: true

RSpec.describe 'bounded dissection', :fuzz do
  around do |example|
    previous = ENV['REDHOUND_STRICT']
    ENV['REDHOUND_STRICT'] = '1'
    example.run
  ensure
    ENV['REDHOUND_STRICT'] = previous
  end
  it 'handles truncation and deterministic mutations without internal exceptions' do
    count = Integer(ENV.fetch('FUZZ_ITERATIONS', '10000'))
    random = Random.new(Integer(ENV.fetch('FUZZ_SEED', '1')))
    seeds = [ether(arp, type: 0x0806), ether(ipv4(udp('hello', dport: 9999))),
             ether(ipv6(tcp('GET / HTTP/1.1\r\n\r\n', dport: 80), next_header: 6), type: 0x86dd),
             ether(ipv4(icmp_echo, proto: 1))]
    Dir[File.expand_path('../fixtures/pcap/*.pcap', __dir__)].each do |path|
      Redhound.open(path) { |reader| reader.each { |packet| seeds << packet.data if seeds.length < 200 } }
    end
    seeds.each do |bytes|
      (0..bytes.bytesize).each { |n| Redhound.dissect(bytes.byteslice(0, n)).to_h }
    end
    count.times do |i|
      bytes = i.even? ? seeds.sample(random: random).dup : random.bytes(random.rand(0..256))
      random.rand(1..4).times do
        break if bytes.empty?
        pos = random.rand(bytes.bytesize)
        bytes.setbyte(pos, random.rand(256))
      end
      linktype = [1, 0, 101, 108, 113, 276, 228, 229].sample(random: random)
      packet = Redhound.dissect(bytes, linktype: linktype)
      packet.to_h
      Redhound::Output::Summary.new.line(packet)
    rescue StandardError => e
      raise "seed=#{ENV.fetch('FUZZ_SEED', '1')} iteration=#{i} linktype=#{linktype} hex=#{bytes.unpack1('H*')}: #{e.class}: #{e.message}"
    end
  end
  it 'never calls packet APIs that can abort Ruby' do
    runtime = Dir[File.expand_path('../../lib/**/*.rb', __dir__)].map { |path| File.read(path).lines.reject { |line| line.lstrip.start_with?('#') }.join }.join
    expect(runtime).not_to match(/\bMSG_TRUNC\b|\.recvmsg\b|\brequire\s+['"]fiddle/)
  end
end
