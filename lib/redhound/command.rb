require "optparse"
require "socket"

module Redhound
  class Command
    def initialize
      @options = { ifname: nil }
    end

    def run(argv)
      parse(argv)
      if @options[:ifname].nil?
        warn "Error: interface is required"
        exit 1
      end
      Receiver.run(ifname: @options[:ifname])
    end

    def parse(argv)
      OptionParser.new do |o|
        o.banner = <<~'BANNER'
             ___         ____                     __
            / _ \___ ___/ / /  ___  __ _____  ___/ /
           / , _/ -_) _  / _ \/ _ \/ // / _ \/ _  /
          /_/|_|\__/\_,_/_//_/\___/\_,_/_//_/\_,_/
          Version: #{Redhound::VERSION}
          Dump and analyze network packets.

          Usage: redhound [options] ...
        BANNER
        o.separator ""
        o.separator "Options:"
        o.on("-i", "--interface INTERFACE", "name or idx of interface") { |v| @options[:ifname] = v }
        o.on("-D", "--list-interfaces", "print list of interfaces and exit") { list_interfaces; exit }
        o.on("-h", "--help", "display this help and exit") { puts o; exit }
        o.on("-v", "--version", "display version information and exit") { puts "Redhound #{Redhound::VERSION}"; exit }
        o.on_tail
        o.parse!(argv)
      end
    end

    private

    def list_interfaces
      ::Socket.getifaddrs.each { |ifaddr| puts ifaddr.name }
    end
  end
end
