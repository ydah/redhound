# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # Enumerable pcap/pcapng reader; inherited capture-source methods include stop and close.
  class Reader < Capture::FileSource
  end
end
