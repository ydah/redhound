# frozen_string_literal: true

module Redhound
  module Source
    class Socket
      def initialize(socket:)
        @socket = socket
      end

      def next_packet(size = 2048)
        @socket.recvfrom(size)
      end
    end
  end
end
