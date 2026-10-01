---
title: CLI usage
description: Capture options, output formats, rotation, privileges, and platform limits.
permalink: /guide/cli/
---
# Using Redhound

Ruby 3.3 or later is required. File analysis needs no capture privileges.
Live capture uses Linux AF_PACKET or macOS BPF devices and normally requires
root or an appropriate device/capability grant. Runtime dependencies are Ruby's
standard libraries; neither libpcap nor a native extension is required.

```sh
redhound -D
sudo redhound -i any 'tcp port 443'
sudo redhound -i en0 -c 100 -w trace.pcapng
sudo chown "$(id -un)" trace.pcapng
redhound -r trace.pcapng -T tree
redhound -r trace.pcap -T ndjson 'udp port 53'
redhound -r trace.pcap -T fields -e ip.src -e tcp.dstport
redhound -r trace.pcap --stats conv,tcp --stats io,1
redhound -r trace.pcap --follow tcp,ascii,0
```

Options must precede the filter expression. Quote filters containing shell
operators. Addresses are numeric by default; `-N` enables name resolution.
`--help` lists every option. `--list-protocols` lists registered protocols and
their declared fields. Dynamic fields also appear in detailed and JSON output.

## Options for tcpdump users

| tcpdump | Redhound |
| --- | --- |
| `-i`, `-D`, `-c`, `-s`, `-p`, `-B`, `-Q` | Same purpose; `-i any` is Linux only |
| `-r`, `-w`, `-U` | Read/write pcap or pcapng; `-` selects stdin/stdout |
| `-C`, `-G`, `-W` | Size/time rotation and file count |
| `-e`, `-q`, `-v`, `-vv`, `-vvv` | Link header, short output, increasing detail/checksums |
| `-t` through `-ttttt` | No time, epoch, delta, date/time, elapsed time |
| `-x`, `-xx`, `-X`, `-XX` | Hex/ASCII, optionally including the link header |
| `-F`, `-d`, `-dd`, `-ddd` | Filter file and cBPF listing |
| `-Z USER` | Drop user/group privileges after opening capture and output |

See [supported capture filters](FILTERS.md). Capture filters select packets;
Wireshark display filters are not supported. `--decode-as udp.port==8443,dns`
overrides port dispatch. `-I plugin.rb` loads a Ruby dissector before capture.

## Saving and rotation

`-w` alone saves raw packets without dissection. Add `-T summary` or `-V` to
also display them. Binary output to stdout cannot be combined with text output.
`--format pcapng` overrides the extension. pcapng preserves interface identities,
nanosecond timestamps, packet directions and available drop statistics.

`-C` uses decimal megabytes; `-G` uses seconds. Rotated files receive a five-digit
sequence before the extension. With `-C -W`, names form an overwrite ring.
With `-G -W` alone, capture stops after the requested number of files. `-G`
expands strftime directives in the base name. Rotation happens when the next
packet arrives. `--post-rotate-command 'gzip -f'` invokes an argument vector,
appending the closed filename; it does not invoke a shell. Input files and their
aliases are protected from output truncation, including rotated destinations.

## Analysis and termination

Displayed TCP packets receive stream IDs and analysis flags. IP fragments and
TCP application messages are reassembled within bounded state. Conflicting
IPv6 overlaps discard the datagram; IPv4/TCP retain first-seen bytes and report
conflicts. Incomplete, expired or evicted state is diagnosed, not retained
indefinitely. `--follow tcp,raw,N` emits the selected stream bytes without headers;
ASCII and hex modes label the endpoints and directions.

Statistics accept `io,SECONDS`, `conv,eth|ip|ipv6|tcp|udp`,
`endpoints,eth|ip|ipv6|tcp|udp`, or `phs`; options can be repeated. Packet counts
and byte totals use captured packets and original frame lengths. SIGUSR1 (and
SIGINFO on macOS) prints a statistics snapshot; SIGINT/SIGTERM close output and
capture sources cleanly. Capture statistics go to stderr. Exit status is 0 on
success, 1 on capture/file failures and 2 on invalid arguments.

## Platforms and limits

Linux `auto` uses TPACKET_V3 on x86_64 and aarch64 and falls back to the socket backend when
mapping is unavailable. Other Linux architectures default to sockets; `ring`
can be selected explicitly. macOS uses BPF, with native timestamp precision
reported by the device. Linux socket capture cannot recover NIC-stripped VLAN
tags; choose the ring backend for that metadata.
Ruby 4.0's `IO::Buffer.map` rejects packet sockets, so `auto` uses socket capture
and explicit `ring` reports the mapping limitation. Use Ruby 3.3/3.4 for ring
capture. If using sockets, disable receive VLAN offload on the receiving
interface when VLAN tags are required (`ethtool -K IF rxvlan off`).

Windows, Wi-Fi monitor mode, packet transmission, TLS decryption, complete
HTTP/2/QUIC dissection, display-filter syntax and a TUI are outside v2's scope.
See [release validation status](VALIDATION.md) before promoting a prerelease.
