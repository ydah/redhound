# Release validation

## 2.0.0.rc1

The implementation covers the v2 roadmap: the packet/dissector API, network and
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
measured 99.90%. See [benchmarks](../bench/RESULTS.md)
for throughput figures and measurement limits.

## Remaining GA acceptance gates

- Run a 24-hour continuous capture stability check.
- Run a 72-hour rotation soak and record RSS, descriptor counts and drop rates.
- Run an hour of high-load aarch64 socket/ring comparison before changing its
  automatic backend default.
- Confirm x86_64 single-core throughput and live drop targets on the specified
  workload; file benchmarks alone cannot establish loss-free live throughput.
- Keep rc1 available for two weeks, classify reports, and fix critical/high
  failures before GA.

These elapsed-time/hardware gates are not marked complete by unit tests.
Promote to 2.0.0 only after their evidence is recorded. A 1.x maintenance
end date is set at GA plus six months; no maintenance branch is created by this
main-only implementation.
