# rbs_inline: enabled
# frozen_string_literal: true

require 'etc'

module Redhound
  # @api private
  module CLI
    # @api private
    module Privileges
      # @rbs (String user) -> void
      def self.drop(user)
        account = Etc.getpwnam(user)
        raise ConfigurationError, 'privilege target must not be root' if account.uid.zero?
        Process.initgroups(account.name, account.gid)
        Process::Sys.setgid(account.gid)
        Process::Sys.setuid(account.uid)
        begin
          Process::Sys.setuid(0)
        rescue Errno::EPERM
          return
        end
        raise CaptureError, 'failed to drop root privileges permanently'
      rescue ArgumentError => e
        raise ConfigurationError, e.message
      end
    end
  end
end
