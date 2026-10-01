# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Linux
      # @api private
      module Cooked
        # @rbs (SockaddrLL address) -> String
        def self.header(address)
          [address.protocol, 0, address.index, address.hatype, address.pkttype, address.address.bytesize, address.address].pack('n n N n C C a8')
        end
      end
    end
  end
end
