# frozen_string_literal: true

module Redhound
  class Resolver
    class << self
      def resolve(ifname:)
        new.resolve(ifname:)
      end
    end

    def resolve(ifname:)
      if RUBY_PLATFORM =~ /darwin/
        raise 'Not implemented yet'
      else
        Redhound::Builder::Socket.build(ifname:)
      end
    end
  end
end
