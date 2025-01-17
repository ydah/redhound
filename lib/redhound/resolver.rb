# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  class Resolver
    class << self
      # @rbs (ifname: String) -> void
      def resolve(ifname:)
        new.resolve(ifname:)
      end
    end

    # @rbs (ifname: String) -> Redhound::Source::Socket
    def resolve(ifname:)
      if RUBY_PLATFORM =~ /darwin/
        raise 'Not implemented yet'
      else
        Redhound::Builder::Socket.build(ifname:)
      end
    end
  end
end
