---
title: Migration from 1.x
description: Move from the Redhound 1.x API and CLI to the v2 packet model.
permalink: /guide/migration/
---
# Migrating from 1.x

Redhound 2 replaces the former Analyzer/Builder/L2/L3/L4 classes with Packet,
Layer, Field and Dissector. Those internal classes have been removed. Migrate
library integrations to the APIs in [API.md](API.md). Ruby 3.3 remains the
minimum version.

The default CLI output is now a one-line summary. Use `-V` or `-T tree` for
packet details. `-v` now increases verbosity; use `--version` to print the
version. Numeric addresses remain the default.

`-w` alone records packets without printing or parsing them. Use `-w capture.pcap
-T summary` to save and display. Unknown protocols remain accessible as Data
layers, and malformed headers produce diagnostics instead of terminating the
capture. Payload text escapes terminal control bytes.

Interface indexes and Linux `any` are supported. Linux loopback duplicates are
removed. Capture timestamps come from the kernel; captured and original packet
lengths are recorded separately. pcapng supports multiple interfaces and metadata.

Version 2 is currently a prerelease. The two-week RC evaluation and long capture
soak gates remain prerequisites for GA; a 1.x maintenance deadline will be
announced when GA is published.
