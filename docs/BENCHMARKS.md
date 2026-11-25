# Hellhound benchmarks

These local measurements were recorded on 2026-10-05. They describe the provider
fetch-ownership change on one machine and are not deployment capacity guarantees.

Scope: provider cache cost, token validation and key refresh. Correctness
references and conformance receipts are in [ORACLE.md](ORACLE.md); both documents
use the same local HTTPS provider fixtures. The design's
[benchmark method](design/design.typ) states the rules, [ADR 0017](adr/0017-benchmarks-are-local-observations-without-thresholds.md)
records why no result gates a change, and [`AGENTS.md`](../AGENTS.md) lists the
commands. Raw output of a new run belongs beside its summary as a non-markdown
file.

The immutable [measurement receipt](https://github.com/gleam-dream/hellhound/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/PROGRESS.md#round-9-provider-fetch-ownership-2026-10-05)
records the numbers and method. [ADR 0007](adr/0007-cache-incarnation-ownership.md)
explains the ownership requirement and allocation cost. The receipt names
baseline revision `99531f3`; its own revision is
`f3847d102c0db9f66e4d4a72a9c7b3028507c7ac`. It does not identify the exact measured
after revision separately.

## Token validation, key refresh and cached reads

The runtime was OTP 28 with four online schedulers and no concurrent stress gate.
The CPU, RAM, operating system and exact OTP patch version were not recorded.

| Workload                                         |              Before |               After | Aggregation                                               |
| ------------------------------------------------ | ------------------: | ------------------: | --------------------------------------------------------- |
| One client validating a cached JWT               | 2,568 validations/s | 2,528 validations/s | Median of three warmed runs; 3,000 validations/run        |
| Four clients validating cached JWTs concurrently | 9,761 validations/s | 9,737 validations/s | Median of three warmed runs; 3,000 validations/client/run |
| 100 sequential TLS signing-key refreshes         |             5.232 s |             5.223 s | Median of three warmed runs                               |
| One cache, sequential snapshot reads             |      20.259 µs/read |      20.230 µs/read | Median of five alternating pairs; 20,000 reads/cache/run  |
| Four caches, interleaved snapshot reads          |      20.581 µs/read |      20.798 µs/read | Median of five alternating pairs; 20,000 reads/cache/run  |

These values come from the [recorded comparison](https://github.com/gleam-dream/hellhound/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/PROGRESS.md#round-9-provider-fetch-ownership-2026-10-05).
Token-validation and refresh ranges overlapped. Snapshot runs used 1,000 warmup
reads per cache in the same VM, loading baseline and changed provider BEAM code
between fully stopped fixtures. The one-cache ranges were 17.057–20.337 µs/read
before and 19.898–20.346 after. Four-cache ranges were 20.324–20.759 before and
20.587–21.617 after.

After explicit garbage collection, cache memory was 5,768–8,784 bytes in both
sets of paired samples. Heap allocation bins varied; the observations do not
establish a memory improvement. Idle and completed-burst caches had no active
lifecycle monitors or queued messages.

## Snapshot reads without the cache process (2026-11-24)

Before this change every validation asked the cache process for its snapshot
through a spawned proxy process. The cache now publishes the accepted snapshot
as a persistent term and the caller reads it directly.

Both sides were measured back to back with `scripts/benchmark` on one Apple M4
laptop (10 cores, 16 GB, macOS 27.0), OTP 29 with four schedulers, Gleam 1.19.2.
The baseline is revision `13c65db`. Other builds ran on the machine at the same
time, so the figures are noisy; one run in three of the changed code was about
20% slower in the concurrent rows, and the ranges show it. "After" is six
runs. "Before" is six runs for the four-caller and snapshot rows and three for
the other two, whose first three outputs were not kept.

| Workload                                     |                 Before |                  After |
| -------------------------------------------- | ---------------------: | ---------------------: |
| One client, one caller, validations/s        | 13,452 (11,834–13,615) | 14,525 (14,256–14,751) |
| One client, four callers, validations/s      | 40,851 (37,265–41,596) | 50,642 (38,916–51,309) |
| Four clients, one caller each, validations/s | 45,471 (45,183–45,554) | 49,287 (39,110–50,128) |
| One cache, sequential snapshot read          |    3.65 µs (3.59–3.70) | 0.060 µs (0.055–0.064) |

Each cell is the median and the range. Median latency of one validation with one
caller went from 74 µs to 69 µs: signature verification dominates, and the
snapshot read was about 5% of it. With four callers of one client the 95th
percentile went from 153–167 µs to 92–95 µs in the undisturbed runs (162 and
201 µs in the two disturbed ones). The 2026-10-05 table above was recorded on
other hardware and OTP 28 and is not comparable with these rows.

## Large signing-key sets

A separate [five-pair forwarding measurement](https://github.com/gleam-dream/hellhound/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/PROGRESS.md#large-key-set-forwarding-measurement)
compared a monitored direct worker with the real fetch guardian on OTP 28 with
four schedulers. Each pair alternated order and used generated public P-256 keys
with distinct identifiers. Worker-owned terms avoided literal-sharing shortcuts.
The following medians include decoding a serialized term and delivering it:

| Keys  | Direct worker |     Guardian | Additional time |
| ----- | ------------: | -----------: | --------------: |
| 1     |       7.46 µs |     14.18 µs |         6.72 µs |
| 100   |     244.30 µs |    296.16 µs |        51.86 µs |
| 1,000 |   2,448.96 µs |  3,003.75 µs |       554.79 µs |
| 5,000 |  14,815.49 µs | 19,364.45 µs |     4,548.96 µs |

The 5,000-key fixture was 828,903 JSON bytes, below the 1 MiB response limit, but
its decoded flat term was 2,160,024 bytes. A guardian paused before forwarding
occupied 2,546,568 bytes after garbage collection. That excludes worker, cache
and transport memory and is not peak memory.

For the actual JWKS parsing-and-delivery workload at 5,000 keys, medians were
1.435 s direct and 1.410 s guarded. The ranges overlapped: 1.412–1.778 s direct
and 1.395–1.691 s guarded. Parsing dominated; these samples do not show a
speedup. The comparison isolates worker delivery, not two complete Hellhound
releases. See the [receipt](https://github.com/gleam-dream/hellhound/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/PROGRESS.md#large-key-set-forwarding-measurement)
for the recorded method. Its standalone synthetic harness, iterations per pair
and hardware details were not retained in this checkout.

## Run the retained benchmark entry points

From the Hellhound repository, open an Erlang shell with four schedulers:

```sh
ERL_FLAGS="+S 4" nix develop -c gleam shell
```

Then run:

```erlang
hellhound_fetch_ownership_test:benchmark().
hellhound_fetch_ownership_test:snapshot_benchmark().
```

The [retained source](../test/hellhound_fetch_ownership_test.erl) creates its own
local HTTPS test provider and stops each client fixture. `benchmark/0` warms
100 validations per client, measures 3,000 per client for one and four clients
and 3,000 per caller for four concurrent callers of one client,
reports throughput and latency percentiles, and measures 100 sequential key
refresh requests. The untimed `bookkeeping/0` setup makes the one key fetch
before timing starts; under the unknown-key cooldown, the 100 timed requests
then return the cached snapshot without fetching. The retained 100-refresh row
above measures the earlier per-kid policy and is not comparable with new
samples.
`snapshot_benchmark/0` warms 1,000 reads per cache and measures 20,000
per cache for one and four caches.

These commands produce new samples for the current checkout. They do not recreate
the historical baseline comparison or the separate large-key-set experiment.
Repeat runs and retain their raw output, source/dependency revisions and machine
configuration when reporting a new result. Neither benchmark is a correctness-gate
performance threshold.
