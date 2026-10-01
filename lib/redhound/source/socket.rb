# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  module Source
    class Socket
      BUFFER_SIZE     = 256 * 1024 # lo (MTU 65536) や GRO で 64KiB 超のフレームが来るため
      SIOCGSTAMPNS    = 0x8907     # 直前に受信したパケットのカーネル時刻 (struct timespec)
      PACKET_OUTGOING = 4
      ARPHRD_LOOPBACK = 772

      # @rbs (socket: ::Socket) -> void
      def initialize(socket:)
        @socket = socket
        enable_timestamp
      end

      # 注意: recvmsg は使えない (Ruby が MSG_CMSG_CLOEXEC を付与し EINVAL)。
      #       MSG_TRUNC も渡してはいけない (Ruby が [BUG] で abort する)。
      # @rbs () -> [String, Time]
      def next_packet
        loop do
          msg, addr = @socket.recvfrom(BUFFER_SIZE)
          _family, _proto, _ifindex, hatype, pkttype = addr.to_sockaddr.unpack('S n l S C')
          # lo では送信と受信の両方が見えるため、送信側を捨てて二重表示を防ぐ (libpcap と同じ挙動)
          next if hatype == ARPHRD_LOOPBACK && pkttype == PACKET_OUTGOING

          return [msg, kernel_timestamp]
        end
      end

      # @rbs () -> void
      def close
        @socket.close
      end

      private

      # 初回の SIOCGSTAMPNS は ENOENT を返すが、以降の受信でタイムスタンプが記録されるようになる
      # @rbs () -> void
      def enable_timestamp
        @socket.ioctl(SIOCGSTAMPNS, "\0" * 16)
      rescue Errno::ENOENT
        nil
      end

      # @rbs () -> Time
      def kernel_timestamp
        buf = "\0" * 16
        @socket.ioctl(SIOCGSTAMPNS, buf)
        sec = buf.unpack1('q') #: Integer
        nsec = buf.unpack1('q', offset: 8) #: Integer
        Time.at(sec, nsec, :nsec)
      rescue SystemCallError
        Time.now
      end
    end
  end
end
