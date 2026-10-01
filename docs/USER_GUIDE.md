---
title: User Guide
description: Install Redhound, capture network traffic, inspect files, and use the packet API from Ruby.
permalink: /guide/
---
# User Guide

Redhound captures, reads, and analyzes network packets in pure Ruby. Use the CLI
to inspect traffic, then use the same packet model in your Ruby application.
This guide walks through installation, your first capture, and common analysis
tasks. The [CLI reference](USAGE.md) lists options and platform details.

> Version 2 is a release candidate. Install it with `--pre` and check the
> [release validation status](VALIDATION.md) before adopting it for production.

## Install Redhound

You need Ruby 3.3 or newer on Linux or macOS. Redhound uses Ruby's standard
libraries at runtime, with no libpcap or native extension to compile.

```sh
gem install redhound --pre
redhound --version
```

For an application managed by Bundler, add the release candidate to your Gemfile:

```ruby
gem 'redhound', '~> 2.0.0.rc2'
```

Run `bundle install`, then prefix CLI commands with `bundle exec`. The CLI
enables YJIT when it is available; `--no-yjit` disables it.

## Read your first capture

Reading a capture file does not need root. If you already have a pcap or pcapng
file, pass its path to `-r`. To try Redhound with a small sample, download the
application-protocol fixture from the release tag:

```sh
curl -fsSL https://raw.githubusercontent.com/ydah/redhound/v2.0.0.rc2/spec/fixtures/pcap/applications.pcap -o sample.pcap
redhound -r sample.pcap -c 3
```

The default format prints one summary per packet. `-c 3` limits the output to
three packets. Inspect the full protocol tree with:

```sh
redhound -r sample.pcap -T tree
```

Addresses are numeric by default. Use `-N` if you want name resolution.

## Capture live traffic

List the available interfaces:

```sh
redhound -D
```

Choose an interface shown by that command. Live capture normally needs root or
capture permissions. On macOS, for example:

```sh
sudo redhound -i en0 -c 100 -w trace.pcapng
```

On Linux, `any` captures across interfaces; you can also use a specific interface
such as `eth0` or `lo`:

```sh
sudo redhound -i any -c 100 -w trace.pcapng
```

Capture files are created with private permissions. After capturing as root,
give your regular account ownership before reading the file:

```sh
sudo chown "$(id -un)" trace.pcapng
redhound -r trace.pcapng -T tree
```

`-w` alone saves packets without printing or dissecting them. Add `-T summary`
to print packets while recording. Press Ctrl+C to stop an unbounded capture;
Redhound closes the capture source and output file and reports capture statistics
on stderr. See [platforms and limits](USAGE.md#platforms-and-limits) for backend
selection and Ruby 4.0's Linux ring limitation.

## Filter packets

Capture filters use tcpdump-style syntax for both saved files and live traffic.
Place options before the filter, and quote expressions containing shell
operators:

```sh
redhound -r sample.pcap 'udp port 53'
redhound -r sample.pcap 'tcp and (port 80 or port 443)'
redhound -r sample.pcap 'host 192.0.2.1'
```

To filter while capturing:

```sh
sudo redhound -i en0 -c 100 'tcp port 443'
```

These are capture filters. Wireshark display-filter expressions such as
`tcp.port == 443` are unsupported. See the [capture-filter reference](FILTERS.md)
for boolean precedence, IPv6 constraints, arithmetic, and byte accesses.

## Choose an output format

Use the format that fits your next step:

| Task | Command |
| --- | --- |
| Quick overview | `redhound -r sample.pcap` |
| Protocol tree | `redhound -r sample.pcap -T tree` |
| Hex and ASCII bytes | `redhound -r sample.pcap -X` |
| A JSON array | `redhound -r sample.pcap -T json` |
| One JSON object per line | `redhound -r sample.pcap -T ndjson` |
| Selected fields | `redhound -r sample.pcap -T fields -e ip.src -e udp.dstport` |

Field names follow Wireshark conventions. List registered protocols and their
declared fields with `redhound --list-protocols`; variable fields also appear in
tree and JSON output. See [protocols and fields](PROTOCOLS.md) for coverage.

## Analyze conversations and streams

Summarize TCP conversations, count endpoints, or report one-second traffic
intervals. Statistics options can be repeated:

```sh
redhound -r sample.pcap --stats conv,tcp
redhound -r sample.pcap --stats endpoints,ip
redhound -r sample.pcap --stats io,1
redhound -r sample.pcap --stats conv,tcp --stats io,1
```

TCP analysis assigns stream IDs. Find `tcp.stream` in tree output, then follow
the stream you need. Stream numbering starts at zero:

```sh
redhound -r sample.pcap -T fields -e tcp.stream
redhound -r sample.pcap --follow tcp,ascii,0
redhound -r sample.pcap --follow tcp,hex,0
```

`--follow tcp,raw,0` writes stream bytes without headers. Analysis uses bounded
state: missing data, truncation, and expired reassembly are reported as
diagnostics. TLS dissection exposes hello metadata; it does not decrypt traffic.

## Save and rotate captures

The output extension selects pcap or pcapng. Use `--format` to select the format
explicitly, including when writing to standard output:

```sh
redhound -r sample.pcap -w copy.pcapng
redhound -r sample.pcap -w - --format pcapng > copy.pcapng
```

pcapng preserves interface identities, nanosecond timestamps, packet directions,
and available drop statistics. Redhound refuses to overwrite its input file.

For a bounded live recording, rotate by size and retain three files:

```sh
sudo redhound -i en0 -w trace.pcapng -C 64 -W 3
```

`-C 64` uses decimal megabytes. `-W 3` with size rotation forms an overwrite
ring: older files are replaced. `-G` selects a time interval in seconds; with
`-G -W` alone, capture stops after the requested number of files. Rotation occurs
when the next packet arrives, so it is not a wall-clock timer for idle traffic.
See [saving and rotation](USAGE.md#saving-and-rotation) for naming and post-rotate
commands.

## Use the Ruby API

Read packets with a block so the reader closes automatically:

```ruby
require 'redhound'

Redhound.open('sample.pcap', filter: 'udp port 53') do |reader|
  reader.each do |packet|
    puts packet.summary
    p packet['ip.src']
    p packet.to_h
  end
end
```

Read and write captures using the same packet model:

```ruby
require 'redhound'

Redhound::Writer.open('dns.pcapng') do |writer|
  Redhound.open('sample.pcap', filter: 'udp port 53') do |reader|
    reader.each { |packet| writer << packet }
  end
end
```

Use `Redhound.dissect(frame_bytes, linktype: :ethernet)` when frame bytes are
already in memory. The [Ruby API reference](API.md) covers live capture, packet
metadata, repeated fields, structured diagnostics, analysis sessions, and custom
dissectors.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Permission denied during live capture | Use root or configure the appropriate device/capability grant. File analysis does not need capture privileges. |
| Permission denied reading a root-owned capture | Transfer ownership with `sudo chown "$(id -un)" trace.pcapng`. Captures are private by default. |
| `any` is unavailable | `any` is Linux only. Select an interface from `redhound -D` on macOS. |
| Ring mapping fails on Linux Ruby 4.0 | Use the automatic socket backend, or use Ruby 3.3/3.4 for ring capture. |
| A filter is rejected | Use capture-filter syntax, place options first, and quote shell operators. |
| Kernel drop counts increase | Narrow the filter, avoid unnecessary display work, and inspect the buffer/backend settings in the CLI reference. |
| A protocol stays as Data | Check supported protocols, truncation diagnostics, and port dispatch. `--decode-as` can override a port's dissector. |

Exit status is `0` on success, `1` for capture/file failures, and `2` for invalid
arguments. Capture statistics and errors go to stderr, leaving structured or
binary stdout available for other tools.

## Next steps

- [CLI usage](USAGE.md): options, tcpdump mapping, privileges, and platform limits.
- [Capture filters](FILTERS.md): filter syntax, arithmetic, and cBPF inspection.
- [Protocols](PROTOCOLS.md): supported protocols, fields, and dissection limits.
- [Ruby API](API.md): readers, writers, packets, analysis, and plugins.
- [Migration](MIGRATION.md): changes from Redhound 1.x.
- [Release validation](VALIDATION.md): completed checks and remaining GA gates.
