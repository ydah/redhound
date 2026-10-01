# rbs_inline: enabled
# frozen_string_literal: true

require_relative 'capture/linktype'
require_relative 'capture/interface'
require_relative 'capture/stats'
require_relative 'capture/source'
require_relative 'capture/linux/constants'
require_relative 'capture/linux/sockaddr_ll'
require_relative 'capture/linux/ifreq'
require_relative 'capture/linux/cooked'
require_relative 'capture/linux/packet_socket'
require_relative 'capture/linux/tpacket_v3'
require_relative 'capture/bsd/constants'
require_relative 'capture/bsd/ifreq'
require_relative 'capture/bsd/bpf_device'
require_relative 'file/format'
require_relative 'file/pcap_reader'
require_relative 'file/pcapng_reader'
require_relative 'file/pcap_writer'
require_relative 'file/pcapng_writer'
require_relative 'file/rotating_writer'
require_relative 'capture/file_source'
require_relative 'reader'

module Redhound
  # @api private
  module Capture
    # @rbs (interface: String | Integer | Interface, ?backend: Symbol | String, ?snaplen: Integer, ?promiscuous: bool, ?buffer_size: Integer?, ?direction: Symbol, ?filter: String?) -> Source
    # @rbs [T] (interface: String | Integer | Interface, ?backend: Symbol | String, ?snaplen: Integer, ?promiscuous: bool, ?buffer_size: Integer?, ?direction: Symbol, ?filter: String?) { (Source) -> T } -> T
    def self.open(interface:, backend: :auto, snaplen: 262_144, promiscuous: true, buffer_size: nil, direction: :inout, filter: nil)
      options = { snaplen:, promiscuous:, buffer_size:, direction:, filter: } #: Hash[Symbol, untyped]
      backend = backend.to_sym
      source = if RUBY_PLATFORM.include?('linux')
                 case backend
                 when :socket then Linux::PacketSocket.new(interface:, **options)
                 when :ring then Linux::TPacketV3.new(interface:, **options)
                 when :auto
                   if RUBY_PLATFORM.start_with?('x86_64-', 'aarch64-', 'arm64-')
                     begin
                       Linux::TPacketV3.new(interface:, **options)
                     rescue SystemCallError, IO::Buffer::AccessError, IO::Buffer::AllocationError, NotImplementedError, UnsupportedPlatform => error
                       warn "redhound: ring backend unavailable (#{error.message}); using socket"
                       Linux::PacketSocket.new(interface:, **options)
                     end
                   else
                     Linux::PacketSocket.new(interface:, **options)
                   end
                 else raise ArgumentError, "invalid Linux capture backend: #{backend}"
                 end
               elsif RUBY_PLATFORM.include?('darwin')
                 raise ArgumentError, "invalid macOS capture backend: #{backend}" unless %i[auto bpf].include?(backend)

                 Bsd::BpfDevice.new(interface:, **options)
               else
                 raise UnsupportedPlatform, "unsupported capture platform: #{RUBY_PLATFORM}"
               end
      return source unless block_given?

      begin
        yield source
      ensure
        source.close
      end
    end

    # @rbs () -> Array[Interface]
    def self.interfaces = Interface.all
  end
end
