# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  module Capture
    module Bsd
      # macOS interface metadata can be queried without opening a BPF device.
      module Ifreq
        SIOCGIFMTU = 0xc0206933 # Verified against sys/sockio.h; sizeof(ifreq) is 32.

        # @rbs (String name, index: Integer, flags: Integer, link_address: String?) -> Interface
        def self.interface(name, index:, flags:, link_address:)
          raise ArgumentError, 'invalid interface name' if name.bytesize >= 16 || name.include?("\0")

          socket = ::Socket.new(::Socket::AF_INET, ::Socket::SOCK_DGRAM, 0)
          bytes = [name].pack('a16') + "\0" * 16
          begin
            socket.ioctl(SIOCGIFMTU, bytes)
          ensure
            socket.close
          end
          mtu = bytes.unpack1('i', offset: 16) #: Integer
          mac = nil # @rbs String?
          if link_address && link_address.bytesize >= 8
            name_length = link_address.getbyte(5) #: Integer
            address_length = link_address.getbyte(6) #: Integer
            if address_length == 6 && link_address.bytesize >= 8 + name_length + address_length
              mac_bytes = link_address.byteslice(8 + name_length, address_length) #: String
              mac_values = mac_bytes.unpack('C6') #: Array[Integer]
              mac = mac_values.map { |value| format('%02x', value) }.join(':')
            end
          end
          linktype = (flags & 8).positive? || name.start_with?('utun') ? 0 : 1
          Interface.new(name:, index:, flags:, mtu:, mac:, linktype:)
        rescue Errno::ENXIO, Errno::ENODEV
          raise InterfaceNotFound, "interface #{name.inspect} not found"
        end
      end
    end
  end
end
