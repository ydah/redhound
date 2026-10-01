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

## Reproducible live acceptance

On Linux with NET_RAW, NET_ADMIN and SYS_ADMIN, `bench/live.rb` creates its own
veth pair and network namespace, sends numbered 600-byte UDP frames and checks
captured bytes, sequence gaps, wire lengths, kernel drops and completion delay:

```sh
sudo ruby --yjit bench/live.rb --duration 10 --rate 200000 --backend ring --out tmp/ring-200k
sudo ruby --yjit bench/live.rb --duration 10 --rate 80000 --backend socket --out tmp/socket-80k
sudo ruby --yjit bench/live.rb --duration 3600 --rate 50000 --backend compare --out tmp/arm-hour
sudo ruby --yjit bench/live.rb --duration 259200 --rate 100 --backend ring --rotate --out tmp/rotation-72h
```

The comparison also requires identical byte digests and kernel timestamps within
1 ms. A sender that cannot produce the requested rate fails acceptance. Capture
processes write pcap to `/dev/null`, or bounded pcapng rotation with `--rotate`;
every completed rotated file is checked with capinfos and tshark. JSON results
and periodic RSS, descriptor and drop samples are retained in the output
directory. Each run needs a new directory. The manual **Live acceptance** GitHub
workflow runs the same check on x86_64 and measures file throughput on one CPU.

Short aarch64 Linux checks on 2026-10-02, Ruby 3.4.11/YJIT, passed 50,000 pps
with both backends (500,000 identical frames each) and 80,000 pps with the socket
backend (800,000 frames), without kernel drops. These are short ARM measurements;
they do not establish the one-hour ARM, x86_64 or 72-hour acceptance gates.
