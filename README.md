# nginxwatch

**Lua 5.x** — nginx/Apache access-log watcher & anomaly detector. Streams a log
(or tails it live), attributes suspicious behavior to source IPs, and emits
machine-readable findings + traffic analytics for your SIEM/pipeline.

[![ci](https://github.com/cognis-digital/nginxwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/nginxwatch/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-Lua-informational)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)**. Single
file, zero dependencies, pure Lua — drop it on any box with a Lua interpreter.
Exits non-zero when it finds something, so it drops straight into cron/CI/alerts.

## Why

`goaccess` shows you pretty traffic dashboards; `fail2ban` bans on regex hits.
`nginxwatch` sits between them: it does **behavioral attribution** — per source
IP it correlates 404 ratios, distinct-path enumeration, sensitive-path probing,
rate spikes, scanner user-agents, 5xx bursts, and large-response egress, then
emits structured findings (JSON/NDJSON/**CEF**/**RFC 5424 syslog**) you can feed
to a SIEM. It also parses `$upstream_response_time` for p50/p95 latency. One pass,
no daemon, no database.

**Scope: defensive / OSINT.** Use only on logs from systems you own or are
authorized to monitor. See [DISCLAIMER.md](DISCLAIMER.md).

## Detections

`scanning` (high 404 ratio) · `enumeration` (many distinct 404 paths) · `probing`
(sensitive paths: `.env`, `wp-login`, `/admin`, `.git`, `/actuator`, `phpmyadmin`,
…) · `flooding` (volume) · `rate_spike` (req/min over threshold) ·
`bad_user_agent` (sqlmap/nikto/nmap/masscan/… or empty UA) · `error_burst` (5xx
concentration) · `large_response` (exfil hint). Full thresholds & false-positive
notes: **[docs/DETECTIONS.md](docs/DETECTIONS.md)**.

## Run

No build step — it's pure Lua:

```bash
lua nginxwatch.lua /var/log/nginx/access.log     # or lua5.4
cat access.log | lua nginxwatch.lua -            # stdin
lua nginxwatch.lua --follow /var/log/nginx/access.log   # live tail
```

## Example output

Running on the bundled `sample.log` (a scanner hammering an IP, a sqlmap client,
and some normal traffic):

```console
$ lua nginxwatch.lua sample.log ; echo "exit=$?"
```
```json
{
  "tool": "nginxwatch",
  "version": "1.0.0",
  "lines": 27,
  "parse_errors": 0,
  "sources": 4,
  "status_class": { "2xx": 5, "3xx": 0, "4xx": 21, "5xx": 1, "other": 0 },
  "top_talkers": [
    { "ip": "10.0.0.5", "requests": 21 },
    { "ip": "198.51.100.7", "requests": 3 },
    { "ip": "203.0.113.9", "requests": 2 },
    { "ip": "2001:db8::1", "requests": 1 }
  ],
  "findings": [
    { "type": "bad_user_agent", "ip": "203.0.113.9", "severity": "high",
      "signature": "sqlmap", "requests": 2,
      "evidence": "user-agent matched scanner signature 'sqlmap'" },
    { "type": "enumeration", "ip": "10.0.0.5", "severity": "high",
      "distinct_404_paths": 21, "requests": 21,
      "evidence": "21 distinct 404 paths (endpoint brute force)" },
    { "type": "scanning", "ip": "10.0.0.5", "severity": "high",
      "requests": 21, "not_found": 21, "ratio_404": 1,
      "evidence": "21/21 requests returned 404 (100.0%)" },
    { "type": "probing", "ip": "10.0.0.5", "severity": "medium",
      "sensitive_hits": 4, "paths": ["/.env","/wp-login.php","/admin","/.git/config"],
      "evidence": "4 requests to sensitive paths" }
  ]
}
exit=2
```

> The JSON above is reformatted for the README; the tool emits a single compact
> line (keys sorted for stable diffs). Every value here is produced by actually
> running `lua nginxwatch.lua sample.log` — nothing is illustrative.

**CEF** for ArcSight / SIEM ingestion (`--format cef`):

```
CEF:0|Cognis Digital|nginxwatch|1.0.0|scanning|scanning from 198.51.100.50|8|src=198.51.100.50 cs1Label=evidence cs1=40/41 requests returned 404 (97.6%) cnt=41 cs2Label=ratio404 cs2=0.976
```

**Syslog** RFC 5424 (`--format syslog`):

```
<35>1 - nginxwatch nginxwatch - bad_user_agent [nginxwatch@0 type="bad_user_agent" src="192.0.2.66" severity="high"] user-agent matched scanner signature 'sqlmap'
```

**NDJSON** (`--format ndjson`) emits the summary as line 1, then one finding per
line — ideal for `filebeat`/`vector`/`jq`.

## Options

```
--min-requests N    only consider IPs with >= N requests   (default 20)
--404-ratio F       flag scanning when 404 fraction >= F    (default 0.4)
--rate N            flag rate_spike at >= N req/min          (default 120)
--window S          time window in seconds for rate calc     (default 60)
--enum N            flag enumeration at >= N distinct 404s   (default 15)
--top N             top-N entries in analytics summary       (default 10)
--xff               trust X-Forwarded-For originating client IP
--format FMT        json | ndjson | cef | syslog             (default json)
-f, --follow FILE   real-time tail mode (poll for appended lines)
--once              in --follow: drain once and exit (no polling)
--max-lines N       stop after N lines (tail safety guard)
-h, --help          show help;  --version  print version
```

## Log formats

Parses nginx/Apache **combined** and **common** formats, tolerates missing
referer/UA and IPv6 remote addresses, and understands a combined +
`$request_time $upstream_response_time` variant (surfaced as p50/p95 latency +
upstream error rate). Unparseable lines are counted in `parse_errors` — never
silently dropped. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install

**Lua first** (any 5.x): `apt install lua5.4` (Debian/Ubuntu) · `brew install lua`
(macOS) · `scoop install lua` or `choco install lua` (Windows), or use WSL.

```bash
# Linux / macOS  — installs `nginxwatch` into /usr/local/bin
sudo sh install.sh                 # or: PREFIX=$HOME/.local sh install.sh
```
```powershell
# Windows — installs nginxwatch.cmd + prints PATH instructions
powershell -ExecutionPolicy Bypass -File install.ps1
```
```bash
# Docker — no local Lua needed
docker build -t nginxwatch .
docker run --rm -i nginxwatch < /var/log/nginx/access.log
```
```bash
# Makefile targets
make test    # run the test suite
make demo    # run all demos
make install # PREFIX-aware install
make lint    # luacheck (skips cleanly if not installed)
```

## Output / exit codes

One JSON object (or NDJSON/CEF/syslog) on stdout. Exit **2** = findings, **0** =
clean, **1** = error — gate pipelines on it:

```bash
nginxwatch access.log > findings.json && echo clean || alert < findings.json
```

## Tests & demos

`lua tests/run.lua` — 74 assertions, self-contained (no busted/luarocks needed),
covering parsing (combined/common/IPv6/XFF/timing), every detector, all four
encoders, threshold tuning, the exit-code contract, and the tail path.
`sh demos/run_all.sh` runs 12 runnable scenarios. Both are wired into CI.

## Docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — parser, aggregator, detectors, tail model, encoders
- [docs/DETECTIONS.md](docs/DETECTIONS.md) — every detection, its thresholds, false-positive notes
- [DISCLAIMER.md](DISCLAIMER.md) — authorized-use / legal notice

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
