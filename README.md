# Redhound [![Gem Version](https://badge.fury.io/rb/redhound.svg)](https://badge.fury.io/rb/redhound) [![Test](https://github.com/ydah/redhound/actions/workflows/main.yml/badge.svg)](https://github.com/ydah/redhound/actions/workflows/main.yml)

Capture and analyze network packets in Pure Ruby. Redhound runs on Linux and
macOS, reads and writes pcap/pcapng, compiles capture filters to cBPF, and
provides summary, tree, hex and JSON output. No libpcap, Fiddle or runtime gem
dependency is required. Ruby 3.3 or later is required.

Version 2 is currently a release candidate. See [validation status](docs/VALIDATION.md)
for remaining GA evaluation gates.

## Installation

```sh
gem install redhound --pre
```

Or add `gem 'redhound', '~> 2.0.0.rc2'` to your Gemfile.

## Usage

```sh
redhound -D
sudo redhound -i any 'tcp port 443'
sudo redhound -i en0 -c 100 -w trace.pcapng
redhound -r trace.pcapng -T tree
redhound -r trace.pcap --stats conv,tcp
redhound -r trace.pcap --follow tcp,ascii,0
```

Live capture normally requires root or capture permissions. File analysis does
not. `-i any` is Linux only; use `lo0`/`en0` on macOS. `-w` alone saves packets
without dissection; add `-T summary` to also print them. Addresses are numeric
by default. Use `-N` to resolve names.

```text
Usage: redhound [options] [filter expression]
    -i, --interface IF               interface name, index or any
    -D, --list-interfaces            list interfaces and exit
    -r, --read FILE                  read pcap or pcapng (- for stdin)
    -c, --count N                    stop after N packets
    -s, --snaplen N                  capture length (default 262144)
    -p, --no-promiscuous             disable promiscuous capture
    -B, --buffer-size KiB            kernel buffer size
    -Q, --direction DIR              capture direction
    -F, --filter-file FILE           read a capture filter
        --capture-backend BACKEND    capture backend
    -w, --write FILE                 write capture (- for stdout)
        --format FORMAT              capture file format
    -C MB                            rotate after MB (decimal)
    -G SECONDS                       rotate at this interval
    -W N                             maximum rotation file count
        --post-rotate-command CMD    command to run after closing each file
    -U, --packet-buffered            flush each packet
    -T, --output-format FORMAT       packet output format
    -V                               show packet details
    -q                               quick output and no capture statistics
        --time-stamp-precision PRECISION
                                     timestamp digits
    -N, --resolve-names              resolve addresses
    -n                               disable address resolution (default)
        --stats SPEC                 io,N / conv,TYPE / endpoints,TYPE / phs
        --follow SPEC                tcp,ascii|hex|raw,N
        --decode-as RULE             e.g. udp.port==8443,dns
    -I, --require FILE               load a custom dissector
    -d                               dump cBPF instructions
    -Z, --relinquish-privileges USER drop capture privileges
        --list-protocols             list protocols and fields
        --debug                      print error backtraces
        --no-yjit                    disable automatic YJIT activation
    -h, --help                       print help
        --version                    print version
  -e [-T fields: FIELD]   link header or selected field (repeatable)
  -v / -vv / -vvv         verbosity and checksum verification
  -t / -tt / -ttt / -tttt / -ttttt   timestamp style
  -x / -xx / -X / -XX     hex dump, with link header / ASCII
```

See [usage and tcpdump option mapping](docs/USAGE.md),
[supported protocols](docs/PROTOCOLS.md), [capture filters](docs/FILTERS.md),
[Ruby API and plugins](docs/API.md), and [migration from 1.x](docs/MIGRATION.md).

## Library

```ruby
require 'redhound'

Redhound.open('trace.pcapng', filter: 'udp port 53') do |reader|
  reader.each { |packet| puts packet.summary }
end

packet = Redhound.dissect(frame_bytes, linktype: :ethernet)
p packet['ip.src']
p packet.to_h
```

## Development

```sh
bundle install
bundle exec rbs collection install --frozen
bundle exec rake
bundle exec yard stats --list-undoc
FUZZ_ITERATIONS=1000000 bundle exec rspec spec/fuzz
sudo -E env "PATH=$PATH" REDHOUND_LIVE=1 bundle exec rspec --tag live
```

Differential tests use tcpdump/tshark as development tools. Fixtures are
regenerated with `ruby -Ilib spec/fixtures/generators/applications.rb` and
`ruby -Ilib spec/fixtures/generators/network.rb`. Update output snapshots with
`UPDATE_GOLDEN=1 bundle exec rspec spec/golden`, then review the changes.
See [benchmark results](bench/RESULTS.md) for reproducible performance checks.

## Contributing and license

Bug reports and pull requests are welcome at [GitHub](https://github.com/ydah/redhound).
Contributors must follow the [code of conduct](CODE_OF_CONDUCT.md).
Redhound is available under the [MIT License](LICENSE.txt).
