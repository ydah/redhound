# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  module Source
    class Socket
      # @rbs (socket: ::Socket) -> void
      def initialize(socket:)
        @socket = socket
      end

      # @rbs (Integer size) -> [String, Addrinfo]
      def next_packet(size = 2048)
        @socket.recvfrom(size)
      end
    end
  end
end
