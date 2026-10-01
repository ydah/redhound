# Changelog

## Unreleased

- Fix crashes on padded ARP, short frames and malformed packet headers.
- Correct IPv4 and IPv6 fields, IP options and transport payload boundaries.
- Display TCP ports, sequence numbers, flags and payload lengths.
- Escape terminal control characters in captured payloads.
- Save packets before analysis and close captures reliably on termination or errors.
- Capture larger frames with kernel timestamps and remove loopback duplicates.
- List interfaces without duplicates and accept interface indexes.

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
