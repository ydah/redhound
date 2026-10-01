# Changelog

## Unreleased

## 2.0.0.rc2 - 2026-10-02

### Bug fixes

- Preserve readable fields in truncated headers and correct ICMP errors, IGMP reports, signed NTP precision, IPv6 extension boundaries and variable field locations.
- Reject malformed TCP options and empty or conflicting HTTP Content-Length values; recognize HTTP when its first line spans segments on nonstandard ports.
- Report incomplete IP/TCP data at EOF and flow eviction, distinguish retransmitted SYN/FIN packets, and handle IPv6 atomic fragments independently.
- Account for retained buffer capacity when enforcing reassembly limits, bound pcapng interface metadata, and release analysis buffers even when output fails.
- Keep capture timeouts and stopping responsive under rejected traffic and idle stdin, preserve partial input records across timeouts, and support replacing file-source filters.
- Preserve wire lengths with attached filters, close capture files after write failures, and prevent metadata errors from corrupting pcapng interface numbering.
- Correct macOS interface MAC/MTU and loopback link types; include interface and direction in packet output and show checksum/TCP options with verbose summaries.
- Preserve negative and expanded-year timestamps and emit valid JSON for invalid UTF-8 diagnostics and interface names; reject invalid packet metadata before file serialization.
- Include empty intervals in IO statistics and keep unknown IP protocol conversations separate.
- Fall back to socket capture when Ruby 4.0 cannot map a packet ring, and explain unavailable explicit ring capture and receive-buffer/VLAN limitations.

## 2.0.0.rc1 - 2026-10-01

### Breaking changes

- Replace the Analyzer/Builder/L2/L3/L4 API with Packet, Layer, Field and the Dissector DSL; use `Redhound.open`, `Redhound.capture` and `Redhound.dissect` for library integrations.
- Use a one-line summary by default. Select `-V` or `-T tree` for detailed output; `-v` controls verbosity and `--version` prints the version.
- Make `-w` save packets without dissection or display unless an output format is also selected.

### Features

- Read and write pcap and pcapng, including stdin/stdout, interface metadata and size/time rotation.
- Capture on macOS BPF devices and Linux socket/TPACKET_V3 backends, including Linux `any`, directions, snaplen and drop statistics.
- Compile tcpdump-style capture filters to validated cBPF for kernel capture and file filtering; support filter files and instruction dumps.
- Decode VLAN/QinQ, LLC/SNAP, cooked/null/raw links, IPv6 extensions, ICMPv6/NDP, IGMPv3, DNS/mDNS/LLMNR, DHCP, NTP, HTTP/1.x, TLS hellos, GRE and VXLAN.
- Track flows, reassemble IP fragments and TCP application messages, report TCP analysis flags/RTT, and follow TCP streams as ASCII, hex or exact bytes.
- Add tree, hex, JSON/NDJSON and selected-field output, conversation/endpoint/interval/protocol statistics, decode-as overrides and custom Ruby dissectors.
- Support privilege dropping after capture setup and write capture files with private permissions.

### Bug fixes

- Fix crashes on padded ARP, short frames and malformed packet headers.
- Correct IPv4 and IPv6 fields, IP options and transport payload boundaries; label ICMP types/codes and avoid false checksum failures on incomplete IPv6 fragments.
- Display TCP ports, sequence numbers, flags and payload lengths.
- Escape terminal control characters in captured payloads.
- Save packets before analysis and close captures reliably on termination or errors.
- Capture larger frames with kernel timestamps and remove loopback duplicates.
- List interfaces without duplicates and accept interface indexes.
- Protect read inputs and their aliases from rotated-output overwrites, validate filters on empty captures, and stop stdin reads cleanly on termination.
- Decode foreign-endian loopback capture headers correctly and preserve original wire lengths for truncated VLAN packets.
- Handle HEAD responses and pipelined HTTP correctly, reassemble HTTP on nonstandard ports, and report missing or incomplete TCP data at FIN and EOF.

## 1.0.1 - 2025-01-17

- Fix an NameError in Redhound::L3::Arp

## 1.0.0 - 2025-01-16

- Add ARP header support.
- Add IPv6 header support.
- Improve formatting of packet output.
- Remove debug print statement from IPv4 header parsing.

## 0.2.0 - 2025-01-03

- Add option to write packets to file as PCAP Capture File Format.

## 0.1.0 - 2024-11-05

- Initial release
