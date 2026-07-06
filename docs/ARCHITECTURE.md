# Architecture

`nginxwatch` is a single Lua module (`nginxwatch.lua`) with no dependencies. It
runs as a CLI (`os.exit(M.main(arg))`) but is also `require()`-able, which is how
the test suite drives it. The pipeline is four stages:

```
  raw lines ──▶ parse_line ──▶ aggregate ──▶ detect ──▶ render
                (parser)       (aggregator)  (engine)   (encoders)
                                    │
                                    └──▶ summarize (analytics)
```

## 1. Parser (`M.parse_line`)

Line-oriented and format-tolerant. It does not assume a fixed field count;
instead it anchors on structural landmarks:

- **remote address** = first whitespace token (handles IPv4 and IPv6).
- **timestamp** = the `[...]` bracketed field, parsed by `M.parse_time`.
- **request line** = the first `"..."` quoted field, split into
  method / path / proto (a malformed request line is kept verbatim as `path`).
- **status + bytes** = the two tokens after the request quote; `-` bytes → 0.
- **referer + user-agent** = the next two quoted fields (combined format).
  Absent in "common" format — handled gracefully.
- **timing** = optional `$request_time` / `$upstream_response_time`, recognized
  either as `rt=`/`urt=` tags or as trailing space-separated floats after the
  user-agent (the common nginx `log_format` convention).

Supported formats: nginx/Apache **combined**, **common**, and a **combined +
upstream-timing** variant. Unparseable lines are counted (`parse_errors`) with
up to 5 samples retained — the count is surfaced in every summary so silent data
loss is impossible.

### Timestamp handling

`M.parse_time` converts `[10/Oct/2000:13:55:36 -0700]` to epoch seconds using
Howard Hinnant's `days_from_civil` algorithm (no reliance on `os.time`, which is
timezone-sensitive and non-portable). The `±HHMM` offset is applied so all
timestamps normalize to UTC — this makes per-minute rate buckets correct across
mixed-timezone logs.

## 2. Aggregator (`M.new_aggregator` / `M.aggregate`)

Single pass, O(n) in lines. Maintains:

- **per-IP stats**: totals, 404 count, distinct-404 set, 5xx count, sensitive-path
  hits, per-minute request buckets (for peak rpm), bad/empty UA flags, max bytes.
- **global stats**: status-class distribution (2xx/3xx/4xx/5xx/other), path
  frequency, user-agent frequency, minute buckets, upstream-timing samples.

Memory is bounded by cardinality (distinct IPs, paths, UAs, minutes), not by log
size, so streaming a large file stays flat in the common case.

## 3. Detection engine (`M.detect`)

Pure function of the aggregator state; returns a list of finding tables. Every
detector is threshold-driven (see `docs/DETECTIONS.md`) and every finding carries
`type`, `ip`, `severity`, and a human-readable `evidence` string. Output is
sorted deterministically (severity desc, then type, then IP) so JSON diffs are
stable across runs — important for snapshot testing and CI.

## 4. Analytics (`M.summarize`)

Builds top-N talkers/paths/user-agents, the status-class histogram,
requests-per-minute time series, and — when upstream timing is present — p50/p95
latency, max, and upstream error rate. Percentiles use the nearest-rank method on
the sorted sample set.

## 5. Output encoders (`M.encoders`)

- **json** (default): one report object `{summary..., findings:[...]}`. Encoded by
  a small embedded encoder with correct string escaping and stable, sorted key
  order (no hand string-concatenation, so no escaping bugs).
- **ndjson**: newline-delimited — first line is the summary (`record:"summary"`),
  then one object per finding (`record:"finding"`). Ideal for log shippers.
- **cef**: ArcSight Common Event Format (`CEF:0|Cognis Digital|nginxwatch|...`),
  header pipes and extension `=`/`\` escaped per the spec.
- **syslog**: RFC 5424 lines (`<PRI>1 - host app procid msgid [SD] MSG`) with a
  `[nginxwatch@0 ...]` structured-data element; PRI uses facility 4 (security).

## Streaming / tail model (`M.follow`)

`--follow` polls the file's size and re-reads only appended bytes (`seek` to the
last read position). It detects truncation/rotation (file shrank → restart from
0). Findings are re-computed each poll and **deduplicated** by a stable key so
only genuinely new findings are emitted incrementally.

Termination is explicit and CI-safe: the loop stops on `--once` (drain then
exit), on `--max-lines N`, or after `max_iterations` idle polls. This guarantees
the tool never hangs a pipeline or test. Polling sleep uses `ping` on Windows and
`sleep` elsewhere, with no third-party dependency.

## Testing

`tests/run.lua` is a self-contained harness (no busted/luarocks needed) that
`require()`s the module and exercises parsing, every detector, the analytics
summary, all four encoders, threshold tuning, the exit-code contract, XFF, and
the tail/`--once` path. It exits nonzero on any failure. Fixtures live in
`tests/fixtures/`.
