# frozen_string_literal: true

require 'optparse'
require 'socket'

module Redhound
  class Command
    def initialize
      @options = { ifname: nil }
    end

    def run(argv)
      parse(argv)
      if @options[:ifname].nil?
        warn 'Error: interface is required'
        exit 1
      end
      Receiver.run(ifname: @options[:ifname], filename: @options[:filename])
    end

    def parse(argv)
      OptionParser.new do |o|
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

    def list_interfaces
      ::Socket.getifaddrs.each { |ifaddr| puts ifaddr.name }
    end
  end
end
