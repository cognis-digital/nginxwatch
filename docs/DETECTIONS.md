# Detections

Every detector is per-source-IP and threshold-driven. Thresholds are CLI-tunable;
the defaults below are conservative starting points, not universal truths — tune
them to your traffic (see the false-positive notes).

| type | default trigger | severity | CLI flag |
|------|-----------------|----------|----------|
| `scanning` | ≥ `min-requests` from an IP **and** 404 ratio ≥ `404-ratio` | high | `--min-requests`, `--404-ratio` |
| `enumeration` | ≥ `enum` **distinct** 404 paths from one IP | high | `--enum` |
| `probing` | ≥ 1 request to a sensitive path | medium (≥5 hits → high) | — |
| `flooding` | total requests ≥ `min-requests` × 5 | medium | `--min-requests` |
| `rate_spike` | peak requests-per-minute ≥ `rate` | high | `--rate`, `--window` |
| `bad_user_agent` | UA matches a scanner signature, or all requests have empty UA (≥ `min-requests`) | high / low | — |
| `error_burst` | ≥ 20 `5xx` responses from one IP | medium | (`err_burst` internal) |
| `large_response` | any response ≥ 10 MiB | low | (`large_bytes` internal) |

Defaults: `min-requests=20`, `404-ratio=0.4`, `rate=120`, `enum=15`.

---

## scanning — high 404 ratio
Content-discovery / fuzzing tools generate many misses. We flag an IP whose 404
fraction crosses `--404-ratio` once it has at least `--min-requests` requests (the
volume gate avoids flagging a single mistyped URL).

**False positives:** a broken deploy (missing assets) or a dead CDN origin can
spike 404s for legitimate clients. Cross-check with `top_paths` — real scanning
hits many *distinct* paths, a broken asset hits the *same* few. Raise
`--404-ratio` or `--min-requests` for chatty single-page apps.

## enumeration — many distinct 404 paths
Complements `scanning`: catches endpoint/directory brute force even when the
overall 404 ratio is diluted by legitimate traffic. Counts **distinct** 404 paths
(a set), so 200 hits to one missing file do *not* trigger it.

**False positives:** aggressive crawlers/link-checkers. Allowlist known bots by
UA in your pipeline, or raise `--enum`.

## probing — sensitive-path access
Any request whose (lowercased) path matches a sensitive signature: `.env`,
`wp-login`, `wp-admin`, `xmlrpc.php`, `/admin`, `.git`, `.svn`, `phpmyadmin`,
`adminer`, `.aws`, `.ssh`, `id_rsa`, `/actuator`, `config.*`, `docker-compose`,
`.htpasswd`, `/server-status`, `/manager/html`, `/jenkins`, `/solr`,
`/vendor/phpunit`, `/cgi-bin`, `/boaform`, `/hnap1`, `/graphql`, and more (see
`M.SENSITIVE` in the source). Severity escalates to `high` at ≥5 hits.

**False positives:** low. A legitimate app that actually serves `/actuator` or
`/graphql` will match — allowlist those specific paths for your own hosts, or
treat probing as informational for known-good endpoints.

## flooding — request volume
Total requests from one IP ≥ `min-requests × 5`. A coarse volume signal; pair it
with `rate_spike` (below) for time-aware detection.

**False positives:** shared NAT egress (offices, mobile carriers), API clients,
your own monitoring. Use `--min-requests` to raise the bar, and consider XFF
(`--xff`) so per-user attribution is correct behind a proxy.

## rate_spike — requests per minute
Uses the parsed timestamps to bucket requests per minute per IP; flags when the
**peak** minute crosses `--rate`. Time-aware, so a burst is caught even if total
volume is modest. `--window` documents the intended aggregation window (buckets
are 60 s).

**False positives:** legitimate bursts (cache stampede, a popular link). Requires
parseable timestamps — logs without a valid time field won't trigger it.

## bad_user_agent — scanner UA / empty UA
Matches known offensive-security tooling UAs: sqlmap, nikto, nmap, masscan,
zgrab/zmap, nessus, openvas, acunetix, netsparker, wpscan, dirbuster, gobuster,
feroxbuster, ffuf, hydra, metasploit, nuclei, whatweb, commix, and more (see
`M.BAD_UA`). Also flags an IP whose requests **all** have an empty UA once it
passes `min-requests` (low severity — empty UA alone is weak signal).

**False positives:** UA strings are trivially spoofable, so absence of a match
means nothing, and a match is high-confidence only for the honest-but-noisy
scanners. `curl`/generic UAs are *not* flagged by default to avoid noise.

## error_burst — 5xx concentration
≥20 `5xx` responses from one IP suggests an attack stressing upstream (or a
scanner triggering app errors).

**False positives:** a genuinely broken upstream will emit 5xx to everyone —
check the global `status_class["5xx"]` and `upstream.error_rate` to distinguish a
site-wide outage from one abusive source.

## large_response — exfil hint
Any single response ≥10 MiB. A weak, informational signal for unusually large
data egress (e.g. a dumped `.sql` or archive).

**False positives:** high for media/download endpoints. This is a *hint* to
correlate with `probing` on the same IP, not a standalone alarm.

---

## X-Forwarded-For (`--xff`)
When enabled, if a line carries an `xff=` tag or a trailing quoted XFF field,
the **originating (leftmost)** client IP is used for attribution instead of the
proxy's address. This is only trustworthy when your edge **overwrites** (not
appends to) the client-supplied `X-Forwarded-For` header — otherwise an attacker
can forge the leftmost value. If you trust N proxies, terminate XFF at your edge.

## Exit-code contract
`2` = at least one finding, `0` = clean, `1` = error (bad file / unknown format).
This makes `nginxwatch access.log && echo clean || alert` a valid CI/cron gate.
