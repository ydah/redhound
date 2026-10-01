<h1 align="center">Redhound</h1>

<p align="center">
  <strong>Capture, inspect, and save network packets in pure Ruby.</strong>
</p>

<p align="center">
  <a href="https://rubygems.org/gems/redhound"><img src="https://img.shields.io/gem/v/redhound?include_prereleases" alt="Gem version including prereleases"></a>
  <a href="https://github.com/ydah/redhound/actions/workflows/main.yml"><img src="https://github.com/ydah/redhound/actions/workflows/main.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="#installation"><img src="https://img.shields.io/badge/Ruby-%3E%3D%203.3-cc342d.svg" alt="Ruby 3.3 or newer"></a>
  <a href="#platforms"><img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-555.svg" alt="Linux and macOS"></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="https://ydah.github.io/redhound/">Website</a> ·
  <a href="https://ydah.github.io/redhound/guide/">User Guide</a> ·
  <a href="#ruby-api">Ruby API</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="#development">Development</a>
</p>

---

Redhound combines tcpdump-style capture filters, protocol dissection, and
pcap/pcapng files in a command-line tool and Ruby library. It runs on Linux and
macOS using Ruby's standard libraries.

> [!NOTE]
> Version 2 is a release candidate. Install it with `--pre` and see
> [release validation](docs/VALIDATION.md) for the remaining GA acceptance checks.

## Features

| Capability | What you can do |
| --- | --- |
| Live capture | Capture on Linux and macOS with kernel timestamps, direction selection, capture filters, and drop statistics. |
| Capture files | Read and write pcap/pcapng, stream through stdin/stdout, and rotate files by size or time. |
| Protocol dissection | Inspect Ethernet, VLAN, IPv4/IPv6, TCP/UDP, DNS, DHCP, NTP, HTTP/1.x, TLS hellos, GRE, and VXLAN. |
| Packet output | Choose a one-line summary, tree, hex dump, JSON/NDJSON, or selected fields. |
| Stateful analysis | Reassemble IP/TCP data, follow TCP streams, and summarize conversations, endpoints, and traffic intervals. |
| Ruby library | Read captures, dissect bytes, access typed fields, and register custom dissectors. |

## Installation

Install the v2 release candidate from RubyGems:

```sh
gem install redhound --pre
redhound --version
```

Or add it to your Gemfile:

```ruby
gem 'redhound', '~> 2.0.0.rc2'
```

Ruby 3.3 or newer is required. The CLI enables YJIT when available. Live capture
requires root or capture permissions. File analysis runs as your regular user.

## Quick start

List the available capture interfaces:

```sh
redhound -D
```

Choose an interface from that list and save 100 packets. This example uses
`en0` on macOS; on Linux, use your device name or `any` for all interfaces.
Capture files are private; give your account ownership after capturing as root.

```sh
sudo redhound -i en0 -c 100 -w trace.pcapng
sudo chown "$(id -un)" trace.pcapng
```

Inspect the saved capture as a protocol tree:

```sh
redhound -r trace.pcapng -T tree
```

The default output is one line per packet. A TCP handshake looks like this:

```text
07:13:20.000000 pcap IP 192.0.2.1.40000 > 192.0.2.2.9999: TCP [S], seq 4294967280, ack 0, win 64240, length 0
07:13:20.010000 pcap IP 192.0.2.2.9999 > 192.0.2.1.40000: TCP [.S], seq 5000, ack 4294967281, win 64240, length 0
07:13:20.020000 pcap IP 192.0.2.1.40000 > 192.0.2.2.9999: TCP [.], seq 4294967281, ack 5001, win 64240, length 0
```

## Everyday usage

| Task | Command |
| --- | --- |
| Show packet details | `redhound -r trace.pcapng -V` |
| Filter DNS traffic | `redhound -r trace.pcapng 'udp port 53'` |
| Export newline-delimited JSON | `redhound -r trace.pcapng -T ndjson` |
| Select packet fields | `redhound -r trace.pcapng -T fields -e ip.src -e tcp.dstport` |
| Summarize TCP conversations | `redhound -r trace.pcapng --stats conv,tcp` |
| Report one-second traffic intervals | `redhound -r trace.pcapng --stats io,1` |
| Follow the first TCP stream | `redhound -r trace.pcapng --follow tcp,ascii,0` |

Place options before the filter expression, and quote filters containing shell
operators. Addresses are numeric by default; `-N` enables name resolution.
`-w` alone saves packets without dissection or display. Add `-T summary` to
print packets while saving them.

Run `redhound --help` for all options, or see the
[usage guide and tcpdump option mapping](docs/USAGE.md).

## Ruby API

Use the same packet model from Ruby:

```ruby
require 'redhound'

Redhound.open('trace.pcapng', filter: 'udp port 53') do |reader|
  reader.each do |packet|
    puts packet.summary
    p packet['ip.src']
    p packet.to_h
  end
end
```

Dissect a frame already held in memory:

```ruby
packet = Redhound.dissect(frame_bytes, linktype: :ethernet)
p packet['ip.src']
p packet.to_h
```

See the [API and plugin guide](docs/API.md) for live capture, writers, filters,
packet metadata, and custom Ruby dissectors.

## Platforms

| Platform | Live capture backend | Interface examples |
| --- | --- | --- |
| Linux | TPACKET_V3 ring or AF_PACKET socket | `eth0`, `lo`, `any` |
| macOS | BPF devices | `en0`, `lo0` |

On Linux, Ruby 4.0 uses the socket backend. Use Ruby 3.3/3.4 for ring capture.
The [platform guide](docs/USAGE.md#platforms-and-limits) covers automatic
backend selection, VLAN metadata, and supported capture-filter syntax.

## Documentation

Visit the [website](https://ydah.github.io/redhound/) and follow the
[User Guide](https://ydah.github.io/redhound/guide/) for installation, your first
capture, and common analysis tasks.

| Guide | Covers |
| --- | --- |
| [User Guide](docs/USER_GUIDE.md) | Getting started, common workflows, and troubleshooting |
| [Usage](docs/USAGE.md) | CLI options, tcpdump mapping, capture files, rotation, and privileges |
| [Protocols](docs/PROTOCOLS.md) | Supported protocols and fields |
| [Capture filters](docs/FILTERS.md) | Filter syntax, examples, and cBPF inspection |
| [Ruby API](docs/API.md) | Packets, readers, writers, analysis, and plugins |
| [Migration](docs/MIGRATION.md) | Moving from the 1.x API and CLI |
| [Release validation](docs/VALIDATION.md) | Completed checks and remaining GA acceptance gates |
| [Benchmarks](bench/RESULTS.md) | Measured results and reproducible performance checks |
| [Changelog](CHANGELOG.md) | User-facing changes by release |

## Development

```sh
git clone https://github.com/ydah/redhound.git
cd redhound
bundle install
bundle exec rbs collection install --frozen
bundle exec rake
```

The Rake task runs RSpec, generates RBS signatures, and checks types with Steep.
Differential tests use tcpdump and tshark as development tools.

The website lives in `docs/`. The Pages workflow builds it with GitHub's Jekyll
action, checks internal links, and publishes main to GitHub Pages. Pull requests
build and check the site without publishing it.

<details>
<summary>Additional checks and fixture maintenance</summary>

```sh
bundle exec yard stats --list-undoc
FUZZ_ITERATIONS=1000000 bundle exec rspec spec/fuzz
sudo -E env "PATH=$PATH" REDHOUND_LIVE=1 bundle exec rspec --tag live
```

Regenerate protocol fixtures with:

```sh
ruby -Ilib spec/fixtures/generators/applications.rb
ruby -Ilib spec/fixtures/generators/network.rb
```

Update output snapshots with `UPDATE_GOLDEN=1 bundle exec rspec spec/golden`,
then review the changes. See [benchmark results](bench/RESULTS.md) for performance
checks.

</details>

## Contributing

[Bug reports](https://github.com/ydah/redhound/issues) and
[pull requests](https://github.com/ydah/redhound/pulls) are welcome.
Contributors must follow the [code of conduct](CODE_OF_CONDUCT.md).

## License

Redhound is released under the [MIT License](LICENSE.txt).
