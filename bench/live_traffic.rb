# frozen_string_literal: true

require 'digest'
require_relative '../spec/support/packet_factory'

# Development-only traffic generation and validation, outside the measured loop.
module RedhoundLiveTraffic
  FRAME_BYTES = 600
  UDP_TAIL = ('RHLOAD'.b + 'x'.b * 544).freeze
  TCP_TAIL = ('RHLOAD'.b + 'x'.b * 532).freeze
  SOURCE_IP = '10.123.0.2'
  DESTINATION_IP = '10.123.0.1'

  def self.templates(source_mac:, destination_mac:, port:, peer_index:)
    counter = [0].pack('Q>')
    udp = PacketFactory.udp(counter + UDP_TAIL, sport: 40_000, dport: port)
    tcp = PacketFactory.tcp(counter + TCP_TAIL, sport: 40_000, dport: port, flags: 0x18)
    pseudo = PacketFactory.ip4(SOURCE_IP) + PacketFactory.ip4(DESTINATION_IP) + [0, 6, tcp.bytesize].pack('CCn')
    checksum = PacketFactory.checksum(pseudo + tcp)
    tcp[16, 2] = [checksum].pack('n')
    frames = [udp, tcp].each_with_index.map do |transport, index|
      PacketFactory.ether(PacketFactory.ipv4(transport, src: SOURCE_IP, dst: DESTINATION_IP, proto: index.zero? ? 17 : 6),
                          src: source_mac, dst: destination_mac)
    end
    { 'udp' => frames[0].unpack1('H*'), 'tcp' => frames[1].unpack1('H*'),
      'tcp_sum' => (~checksum & 0xffff), 'peer_index' => peer_index, 'source_mac' => source_mac, 'port' => port }
  end

  def self.decode_templates(encoded)
    encoded.merge('udp' => [encoded.fetch('udp')].pack('H*'), 'tcp' => [encoded.fetch('tcp')].pack('H*'))
  end

  def self.frame(templates, sequence)
    tcp = sequence.odd?
    bytes = templates.fetch(tcp ? 'tcp' : 'udp').dup
    bytes[tcp ? 54 : 42, 8] = [sequence].pack('Q>')
    if tcp
      sum = templates.fetch('tcp_sum') + ((sequence >> 48) & 0xffff) + ((sequence >> 32) & 0xffff) +
            ((sequence >> 16) & 0xffff) + (sequence & 0xffff)
      sum = (sum & 0xffff) + (sum >> 16) while sum > 0xffff
      checksum = ~sum & 0xffff
      bytes.setbyte(50, checksum >> 8)
      bytes.setbyte(51, checksum & 0xff)
    end
    bytes
  end

  class Verifier
    attr_reader :count, :gaps, :invalid, :first_sequence, :last_sequence, :timestamps, :protocol_counts

    def initialize(start_ns:, duration:, templates: nil, port: nil)
      @start_ns = start_ns
      @end_ns = start_ns + ((duration + 1) * 1_000_000_000).to_i
      @templates, @port = templates, port
      @count = @gaps = @invalid = 0
      @first_sequence = @last_sequence = nil
      @first_timestamp_ns = @last_timestamp_ns = nil
      @timestamps = []
      @protocol_counts = { udp: 0, tcp: 0 }
      @digest = Digest::SHA256.new
    end

    def verify(packet)
      @count += 1
      @digest.update(packet.data)
      @first_timestamp_ns ||= packet.timestamp_ns
      @last_timestamp_ns = packet.timestamp_ns
      @invalid += 1 unless packet.timestamp_ns.between?(@start_ns, @end_ns)
      unless packet.caplen == FRAME_BYTES && packet.original_length == FRAME_BYTES && packet.linktype == 1
        @invalid += 1
        return
      end
      protocol = packet.data.getbyte(23)
      unless protocol == 17 || (@templates && protocol == 6)
        @invalid += 1
        return
      end
      @protocol_counts[protocol == 6 ? :tcp : :udp] += 1
      offset = protocol == 6 ? 54 : 42
      sequence = packet.data.unpack1('Q>', offset: offset)
      @first_sequence = sequence if @count == 1
      @gaps += sequence - @last_sequence - 1 if @last_sequence && sequence > @last_sequence + 1
      @invalid += 1 unless sequence == @count - 1
      @last_sequence = sequence
      if @templates
        @invalid += 1 unless packet.data == RedhoundLiveTraffic.frame(@templates, sequence)
      else
        valid_header = packet.data.unpack1('n', offset: 12) == 0x0800 && packet.data.getbyte(14) == 0x45 &&
                       packet.data.unpack1('n', offset: 16) == 586 && packet.data.unpack1('n', offset: 38) == 566
        valid_header &&= packet.data.unpack1('n', offset: 36) == @port if @port
        @invalid += 1 unless valid_header && packet.data.byteslice(offset + 8..) == UDP_TAIL
      end
      @timestamps << [sequence, packet.timestamp_ns] if sequence % 10_000 == 0
    end

    def complete?(sent)
      sent.positive? && @count == sent && @first_sequence == 0 && @last_sequence == sent - 1 && @gaps.zero? && @invalid.zero?
    end

    def report
      { verified: @count, sequence_gaps: @gaps, invalid: @invalid, first_sequence: @first_sequence,
        last_sequence: @last_sequence, sha256: @digest.hexdigest, timestamps: @timestamps, protocol_counts: @protocol_counts,
        timestamp_range_ns: [@start_ns, @end_ns], first_timestamp_ns: @first_timestamp_ns, last_timestamp_ns: @last_timestamp_ns }
    end
  end
end
