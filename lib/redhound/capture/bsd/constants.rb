# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # @api private
  module Capture
    # @api private
    module Bsd
      # @api private
      module Constants
        # Verified against the macOS SDK's net/bpf.h on arm64 and 64-bit ioctl layout.
        BIOCSBLEN = 0xc0044266
        BIOCGBLEN = 0x40044266
        BIOCSETF = 0x80104267
        BIOCFLUSH = 0x20004268
        BIOCPROMISC = 0x20004269
        BIOCGDLT = 0x4004426a
        BIOCSETIF = 0x8020426c
        BIOCGSTATS = 0x4008426f
        BIOCIMMEDIATE = 0x80044270
        BIOCSSEESENT = 0x80044277
        # Apple XNU bsd/net/bpf_private.h: extended headers expose direction at byte 19.
        BIOCSEXTHDR = 0x8004427c
        BIOCSDIRECTION = 0x8004428b
        BPF_ALIGNMENT = 4
      end
    end
  end
end
