# rbs_inline: enabled
# frozen_string_literal: true

require 'optparse'
require 'socket'

module Redhound
  class Command
    # @rbs () -> void
    def initialize
      @options = { ifname: nil }
    end

    # @rbs (Array[untyped] argv) -> void
    def run(argv)
      parse(argv)
      if @options[:ifname].nil?
        warn 'Error: interface is required'
        exit 1
      end
      Receiver.run(ifname: @options[:ifname], filename: @options[:filename])
    end

    # @rbs (Array[untyped] argv) -> void
    def parse(argv)
      OptionParser.new do |o| # steep:ignore
        o.banner = <<~'BANNER' + <<~BANNER2
             ___         ____                     __
            / _ \___ ___/ / /  ___  __ _____  ___/ /
           / , _/ -_) _  / _ \/ _ \/ // / _ \/ _  /
          /_/|_|\__/\_,_/_//_/\___/\_,_/_//_/\_,_/

        BANNER
          Version: #{Redhound::VERSION}
          Dump and analyze network packets.

          Usage: redhound [options] ...
        BANNER2
        o.separator ''
        o.separator 'Options:'
        o.on('-i', '--interface INTERFACE', 'name or idx of interface') { |v| @options[:ifname] = v }
        o.on('-D', '--list-interfaces', 'print list of interfaces and exit') do
          list_interfaces
          exit
        end
        o.on('-w FILE', 'write packets to a pcap capture file format to file') { |v| @options[:filename] = v }
        o.on('-h', '--help', 'display this help and exit') do
          puts o
          exit
        end
        o.on('-v', '--version', 'display version information and exit') do
          puts "Redhound #{Redhound::VERSION}"
          exit
        end
        o.on_tail
        o.parse!(argv)
      end
    end

    private

    # @rbs () -> void
    def list_interfaces
      ::Socket.getifaddrs.each { |ifaddr| puts ifaddr.name }
    end
  end
end
