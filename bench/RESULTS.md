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

Owned regular-file reads now prefetch at most 64 KiB. Three alternating runs
before/after this change on the same native Ruby 4.0.6/YJIT environment measured
these medians; caller-owned IO, pipes and stdin retain their existing read paths:

| Scenario | Direct reads | Bounded prefetch |
| --- | ---: | ---: |
| Summary | 82,948 pps | 93,830 pps |
| Tree | 45,529 pps | 49,542 pps |
| Filter VM | 449,888 pps | 894,330 pps |
| pcap rewrite | 443,508 pps | 863,095 pps |
| CLI summary with stateful analysis | 47,065 pps | 51,526 pps |

These ARM measurements show the local effect of the change and do not establish
the separate x86_64 throughput gates.

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
veth pair and network namespace, sends numbered 600-byte frames and checks
captured bytes, sequence gaps, wire lengths, kernel drops and completion delay:

```sh
sudo ruby --yjit bench/live.rb --duration 10 --rate 200000 --backend ring --mixed --cpu 0 --verify-after --out tmp/ring-200k
sudo ruby --yjit bench/live.rb --duration 10 --rate 80000 --backend socket --mixed --cpu 0 --verify-after --out tmp/socket-80k
sudo ruby --yjit bench/live.rb --duration 3600 --rate 50000 --backend compare --out tmp/arm-hour
sudo ruby --yjit bench/live.rb --duration 259200 --rate 100 --backend ring --rotate --out tmp/rotation-72h
```

Use an allowed CPU number from `/proc/self/status` when CPU 0 is unavailable.
`--mixed` alternates valid TCP and UDP frames with matching IPv4/TCP checksums.
`--cpu` pins capture processes only; the sender retains its available CPUs.
Verification checks every saved frame against its complete expected bytes,
requires the sequence to start at zero and end at the sent count minus one,
and rejects timestamps outside the capture window. The comparison also requires
identical byte digests and sampled kernel timestamps within
1 ms. A sender that cannot produce the requested rate fails acceptance. Capture
processes write pcap to `/dev/null`, or bounded pcapng rotation with `--rotate`;
every completed rotated file is checked with capinfos and tshark. JSON results
and periodic RSS, descriptor and drop samples are retained in the output
directory. Each run needs a new directory. The manual **Live acceptance** GitHub
workflow runs the same check on x86_64 and measures file throughput on one CPU.
For nonrotating workloads requiring at most 4 GiB, it uses `--verify-after`: captured
pcap records are checked after capture completes, so byte/sequence verification
does not consume the capture/write throughput budget. This temporarily stores
about 1.2 GB at 200,000 pps for ten seconds; generated pcap payloads are excluded
from uploaded artifacts. Longer comparisons verify inline and write to
`/dev/null` to keep storage bounded.

Short aarch64 Linux checks on 2026-10-02, Ruby 3.4.11/YJIT, passed 50,000 pps
with both backends (500,000 identical frames each) and 80,000 pps with the socket
backend (800,000 frames), without kernel drops. These are short ARM measurements;
they do not establish the one-hour ARM, x86_64 or 72-hour acceptance gates.

## Adversarial x86_64 measurements

On 2026-10-02, [run 36882408457](https://github.com/ydah/redhound/actions/runs/36882408457)
measured an AMD EPYC 9V74 GitHub runner, Ruby 3.4.10/YJIT, one CPU:
summary 35,526 pps, tree 20,740 pps and filter 182,368 pps. A separate Ruby 4.0.7
runner measured 27,112 / 16,356 / 163,552 pps respectively. Runner variation
prevents interpreting those differences as Ruby-version or code improvements.
All three file throughput targets remain unmet.

[Run 36882895764](https://github.com/ydah/redhound/actions/runs/36882895764)
used Ruby 3.4 and `--verify-after`: the ring backend saved all 2,000,000 incoming
600-byte frames at a requested 200,000 pps for ten seconds, with zero kernel
drops, sequence gaps or invalid frames. The last block drained 51 ms after the
sender deadline (198,979 pps including that drain). The earlier inline-verifying
run dropped 401,324 frames; its additional byte-checking load is not a
capture/write-only measurement.
This earlier run used UDP only, did not pin the capture process, and used the
older verifier. It establishes a limited capture comparison, not completion of
the mixed-traffic single-core acceptance gate.

[Run 36882900621](https://github.com/ydah/redhound/actions/runs/36882900621)
failed the 80,000 pps socket target on Ruby 4.0: 800,000 frames were sent,
508,827 saved and 232,576 kernel drops reported, with more data pending after
the allowed drain. Missing trailing packets count as failure even when they
cannot appear as an internal sequence gap. Socket throughput remains open.
