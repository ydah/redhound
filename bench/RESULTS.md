# Performance measurements

Generate a fixed 200,000-packet Ethernet/IPv4 TCP+UDP capture (about 600 bytes
per frame), then run each scenario sequentially:

```sh
ruby bench/generate.rb
ruby --yjit bench/dissect.rb --format summary
ruby --yjit bench/dissect.rb --format tree
ruby --yjit bench/dissect.rb --format filter
ruby --yjit bench/dissect.rb --format write
```

2026-10-01, Ruby 4.0.6, arm64-darwin25, YJIT enabled, output `/dev/null`:

| Scenario | Before allocation reduction | After |
| --- | ---: | ---: |
| Summary | 57,950 pps | 77,479 pps |
| Tree | 36,655 pps | 45,949 pps |
| Filter VM (`tcp or udp`) | 423,747 pps | See CI for matching-platform comparisons |
| pcap rewrite | — | 475,527 pps |

The original raw-byte write measurement is excluded: it did not serialize pcap
records. `write` now measures actual Reader→pcap Writer throughput.

StackProf wall sampling identified FieldDefinition construction at 16.7% of
samples and garbage collection at 10.1%. TCP flag definitions are now shared,
fixed-header hashes avoid intermediate key/value arrays, and numeric address
displays avoid unnecessary escape passes. No runtime profiling dependency was
added. To reproduce profiling when StackProf is installed:

```sh
ruby --yjit -rstackprof -e 'StackProf.run(mode: :wall, out: "tmp/summary.dump") { load "bench/dissect.rb" }'
stackprof tmp/summary.dump --text --limit 15
```

The design's initial targets apply to x86_64, one core and YJIT: summary 100,000
pps, tree 30,000 pps, VM 300,000 pps; live ring 200,000 pps and socket 80,000 pps
with no drops. This arm64 macOS summary measurement does not meet the initial
100,000 pps target and is not an x86_64 acceptance result. CI records x86_64 file
numbers and compares against the previous commit, warning at a 15% regression.
The loss-free live targets and sustained aarch64 memory-ordering load require
separate capture/traffic measurements; no throughput or soak result is inferred
from short loopback tests.

## GitHub Actions x86_64 baseline

[Run 36869003834](https://github.com/ydah/redhound/actions/runs/36869003834),
Ubuntu runner, Ruby 3.4.10, YJIT, 200,000 packets, 2026-10-01:

| Scenario | Throughput |
| --- | ---: |
| Summary | 23,982 pps |
| Tree | 13,981 pps |
| Filter VM | 143,058 pps |
| pcap rewrite | 143,008 pps |

The previous commit measured 23,031 summary pps in the same job (a 4.1%
improvement, within runner noise). The initial x86_64 absolute targets were
not reached; performance acceptance remains open for GA. These figures are
reported rather than lowering the targets to classify an unmet gate as passed.
