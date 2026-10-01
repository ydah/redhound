---
title: Release validation
description: Completed release-candidate checks and the remaining GA acceptance gates.
permalink: /guide/validation/
---
# Release validation

## Adversarial review after rc1

The review checked the design, roadmap, work procedures and phase0 patch against
the running implementation, rather than treating a green test suite as proof
that every acceptance gate had passed. Reproduced failures included truncated
headers losing readable fields, incorrect ICMP error fields and dynamic field
locations, missed split HTTP identification, unreported reassembly loss at EOF
and flow eviction, underestimated Ruby buffer capacity, unbounded pcapng
metadata, source timeout violations and capture writer descriptor leaks.
Regression checks accompany the fixes.

The parser fuzz now retains each fixture's real link type during structured
mutations. This prevents tests from stopping at an unrelated link header before
reaching the mutated protocol. `ruby bench/analysis.rb` exercises default state
limits with 60,000 conversations, 40,000 fragmented datagram identities and 80
large TCP streams, checking every update and final buffer release. Its retained
state accounting includes String capacity and object storage. Process RSS is
reported separately: Ruby may retain allocator pages after state is released.

The manual [Live acceptance workflow](https://github.com/ydah/redhound/blob/main/.github/workflows/acceptance.yml) and
`bench/live.rb` record requested/sent/captured counts, gaps, byte digests, kernel
timestamps, drops, RSS and descriptor counts. An insufficient sender rate fails
the check. Controlled aarch64 runs passed 50,000 pps with simultaneous socket and
ring capture and 80,000 pps with socket capture for ten seconds. These short
checks do not replace the hour-long comparison or the x86_64 targets.
The strengthened live harness checks complete expected wire bytes, every
timestamp and the entire zero-based sequence. Its mixed TCP/UDP workload and
capture-only CPU affinity are recorded alongside implementation and harness
digests. The earlier long-running snapshot uses the original UDP workload and
verifier; its comparison requires identical complete-frame digests and sampled
timestamps, and does not establish the new mixed single-core throughput gate.

Local adversarial runtime validation on 2026-10-02 passed all 244 non-live examples
on Linux, with only the macOS-specific interface test skipped. After adding
bounded file prefetch and live-harness regressions, the complete macOS Rake task
passed its 257 examples (20 tshark comparisons are run on Linux), RBS generation
and Steep, with 92.92% total line coverage. Coverage gates passed; the earlier
Linux check measured 92.43% total line coverage. The strengthened one-million-case parser fuzz completed without an
exception. Default state-pressure checks reached exactly 256 MiB accounted
state without exceeding it and released IP/TCP buffers at EOF. Native RSS
reached 308 MiB despite retaining only 107 MiB of Ruby heap before finalization;
this is not reported as a 256 MiB process-RSS guarantee.
The independent [manual CI and million-case fuzz run](https://github.com/ydah/redhound/actions/runs/36885293639)
also passed every job on the adversarial runtime fixes.

The GitHub maintenance configuration now includes weekly Bundler/Actions
dependency updates, actionlint, codespell, strict yamllint, zizmor and Ruby/Actions
CodeQL analysis. Action revisions are pinned and checkout credentials are not
retained. All four lint workflows passed on main; the final CodeQL run succeeded
with no open alerts. HTTP header trimming uses
bounded byte ranges while preserving SP/HTAB-only whitespace semantics; controls
remain visible to malformed-header diagnostics.
After this final parser change, all 16 application-boundary/live-harness examples,
the one-million-case native fuzz run (94.25 seconds), and Steep passed.
All 5,013 binary boundary/random inputs preserved the previous trimming bytes
and encoding. Linux tcpdump/tshark comparisons passed all 26 examples.

Ruby 4.0 introduced an additional restriction in
[`IO::Buffer.map`](https://docs.ruby-lang.org/en/4.0/IO/Buffer.html#method-c-map):
it rejects files with zero size even when a mapping size is supplied. Linux
AF_PACKET sockets have zero file size, so the pure-Ruby ring backend cannot map
them on that runtime. Ruby 3.3/3.4 ring support remains available; Ruby 4.0 uses
the socket backend. No C extension or Fiddle workaround is introduced. Ring
availability on Ruby 4.0 remains an upstream API constraint on full acceptance.

Long-running controlled tests started at 2026-10-01 14:55:57 UTC with a frozen
capture implementation digest
`084591da70d195146b37aff76de7ec9495085d045684decc26da6c34c4ebc20e`:

| Check | Requested workload | Evidence directory | Earliest completion |
| --- | --- | --- | --- |
| aarch64 socket/ring comparison | 50,000 pps, 3,600 seconds | `tmp/acceptance-arm-hour-final` | 2026-10-01 15:55:58 UTC |
| Bounded ring pcapng rotation | 100 pps, 259,200 seconds | `tmp/acceptance-rotation-72h-final` | 2026-10-04 14:55:58 UTC |

These directories contain local private captures and are excluded from Git.
Completion requires the final `result.json` to pass, inspection of the periodic
resource samples, and successful external validation of rotated files. The
controlled veth soak does not establish the separate busy physical-interface
24-hour gate. Results and unfulfilled conditions are recorded explicitly below.

The frozen rotation run first reported 1,178 kernel drops and three ring freezes
at the 4,200-second sample, after zero drops at 3,600 seconds. The macOS power log
records hibernation/wake in that interval with a 10.614-second recovery delay.
This correlation does not isolate the cause, and the run is not loss-free
acceptance evidence. Its periodic resource observations are retained. External
capinfos/tshark inspection now runs after capture closes, validating the three
retained rotation files rather than blocking packet reads at every rotation.
A four-second rotation smoke captured and verified all 4,000 frames without
drops, gaps or malformed records and passed both external tools.

A fresh frozen-source rotation run started at 2026-10-01 16:22:04 UTC, using
capture digest
`7fd49cc4c24664c298c99dbf35276f64e67a1195093c3e1c4f9190fa9d234014`
and harness digest
`55b36abe852549836350d51ea9994b71ded5409794d853777f0634ca6830c760`.
Its private evidence is in `tmp/acceptance-rotation-72h-rc2`; completion cannot
be checked before 2026-10-04 16:22:06 UTC. macOS idle/system sleep assertions
were confirmed on AC power with a 72-hour-plus-ten-minute `caffeinate` timer.
This run is still in progress and does not count as completed acceptance.

The one-hour aarch64 comparison completed successfully: each backend captured
all 180,000,000 frames with zero drops/gaps and the same complete-byte digest.
All 18,000 paired timestamp samples were identical. Ring final drain was
47.638 ms; descriptor counts remained 10/11. Last-half-hour RSS ranged from
31.2–40.2 MiB for sockets and 86.5–86.6 MiB for rings. P6-06 is complete, so
aarch64/arm64 Linux now tries ring capture automatically, retaining socket
fallback when mapping is unavailable. This does not complete the separate
72-hour rotation soak or the mixed x86_64 throughput gates.

The physical macOS en0 interface is active, but `/dev/bpf*` requires administrator
access and `sudo -n` requires a password in this environment. The user could not
start the privileged run, so the 24-hour physical-interface check has not begun.
An independent three-second observation measured approximately 82 packets/s and
21 kB/s; it does not establish a busy workload. `bench/soak.rb` is ready to record
24-hour elapsed time, bounded private pcapng rotation, traffic rates, RSS and
descriptor counts once capture privileges are available. Its one-second Linux
smoke and interrupted-run checks passed, including capinfos/tshark file checks.

## 2.0.0.rc1

The release candidate implements the functional parts of the v2 roadmap: the packet/dissector API, network and
application protocols, Ruby cBPF compiler/VM, Linux socket/ring and macOS BPF
backends, capture files/rotation/privilege drop, bounded stateful analysis,
statistics, follow output and documentation. This is a release candidate,
not a claim that time-dependent GA acceptance checks have completed.

Reproducible checks:

- `bundle exec rake`: RSpec, generated RBS and Steep.
- `REDHOUND_COVERAGE_GATE=1 bundle exec rake`: at least 90% total line coverage
  and 95% protocol line coverage.
- `bundle exec rspec spec/differential`: tcpdump filter match/bytecode parity
  (163 expressions across five link types), tshark protocol and stateful analysis
  field/statistics/follow comparisons.
- `FUZZ_ITERATIONS=1000000 bundle exec rspec spec/fuzz`: strict parser fuzzing.
- `sudo -E env "PATH=$PATH" REDHOUND_LIVE=1 bundle exec rspec --tag live`:
  native capture, attached filters, kernel time, snaplen, stop and loopback.
- `sudo -E env "PATH=$PATH" REDHOUND_LIVE=1 REDHOUND_NETNS=1 bundle exec rspec spec/integration/netns_capture_spec.rb --tag live`:
  Linux veth socket/ring parity and offloaded VLAN restoration/filtering.
- `bundle exec yard stats --list-undoc`: documented public API.
- `actionlint`: test and release workflow validation.

Fixtures are generated without runtime dependencies. Golden output freezes
addresses and timestamps, and validates all JSON snapshots against the schema.
The CI matrix checks Ruby 3.3/3.4/4.0/head, Linux/macOS live capture and tool
comparisons. Scheduled runs execute one million fuzz cases. Benchmark jobs warn
on a summary throughput regression over 15% compared with the previous commit.

Local validation on 2026-10-01: Linux aarch64 Ruby 3.4 passed all 171 non-live
examples, including tcpdump/tshark differential checks, and five live capture
examples using socket and ring backends. Native macOS Ruby 4.0 passed unit,
golden and filter checks; BPF ioctl constants match the installed SDK. Native
BPF loopback and en0 Ethernet capture, attached filters, timestamps, truncation,
termination, privilege dropping and pcapng metadata passed the macOS CI job.
The Linux namespace test passed socket/ring parity and offloaded VLAN checks.
Ruby 3.3/3.4/4.0/head all passed the CI type, signature and coverage gates.
Whole-library line coverage measured 90.92%; isolated protocol line coverage
measured 99.90%. See [benchmarks](https://github.com/ydah/redhound/blob/main/bench/RESULTS.md)
for throughput figures and measurement limits.

## Remaining GA acceptance gates

- Run a 24-hour continuous capture stability check.
- Run a 72-hour rotation soak and record RSS, descriptor counts and drop rates.
- Confirm x86_64 single-core throughput and live drop targets on the specified
  workload; file benchmarks alone cannot establish loss-free live throughput.
- Keep rc1 available for two weeks, classify reports, and fix critical/high
  failures before GA.

These elapsed-time/hardware gates are not marked complete by unit tests.
Promote to 2.0.0 only after their evidence is recorded. A 1.x maintenance
end date is set at GA plus six months; no maintenance branch is created by this
main-only implementation.
