# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Linux
      # @api private
      module Ifreq
        # @rbs (String name, Integer command) -> String
        def self.query(name, command)
          raise ArgumentError, 'invalid interface name' if name.bytesize >= 16 || name.include?("\0")

          socket = ::Socket.new(::Socket::AF_INET, ::Socket::SOCK_DGRAM, 0)
          bytes = [name].pack('a16') + "\0" * 24
          begin
            socket.ioctl(command, bytes)
            bytes
          ensure
            socket.close
          end
        end

        # @rbs (String name, ?index: Integer) -> Interface
        def self.interface(name, index: 0)
          hardware = query(name, Constants::SIOCGIFHWADDR)
          hatype = hardware.unpack1('S', offset: 16) #: Integer
          mac_bytes = hardware.byteslice(18, 6) #: String
          mac_values = mac_bytes.unpack('C6') #: Array[Integer]
          mac = mac_values.map { |value| format('%02x', value) }.join(':')
          flags = query(name, Constants::SIOCGIFFLAGS).unpack1('S', offset: 16) #: Integer
          mtu = query(name, Constants::SIOCGIFMTU).unpack1('i', offset: 16) #: Integer
          Interface.new(name:, index:, linktype: Linktype.for_hardware(hatype), flags:, mtu:, mac:,
                        meta: { hardware_type: hatype })
        rescue Errno::ENODEV, Errno::ENXIO
          raise InterfaceNotFound, "interface #{name.inspect} not found"
        end
      end
    end
  end
end
