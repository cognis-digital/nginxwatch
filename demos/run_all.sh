#!/usr/bin/env sh
# nginxwatch demo suite. Runs every demo scenario and exits 0 on success.
# Detection tools exit 2 when they find something; that is EXPECTED here, so we
# capture and assert exit codes rather than letting `set -e` abort the script.
set -u

# Resolve repo root (parent of this script's dir) so demos work from anywhere.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$DIR/.." && pwd)
cd "$ROOT" || exit 1

LUA="${LUA:-lua}"
NW="$LUA nginxwatch.lua"
FIX="tests/fixtures"
fails=0

hr()  { printf '\n=== %s ===\n' "$1"; }
# assert_exit EXPECTED  -- reads last command's exit via $?
assert_exit() {
  got=$?
  if [ "$got" != "$1" ]; then
    printf '!! expected exit %s got %s\n' "$1" "$got"
    fails=$((fails + 1))
  else
    printf '(exit %s as expected)\n' "$got"
  fi
}

hr "1. Scan the enriched sample log (scanning + enumeration + probing + bad-UA)"
$NW sample.log
assert_exit 2

hr "2. Flooding + rate spike (150 req in one minute from one IP)"
$NW --rate 120 "$FIX/flooding.log"
assert_exit 2

hr "3. Sensitive-path probing"
$NW --min-requests 1 "$FIX/probing.log"
assert_exit 2

hr "4. CEF output (ArcSight / SIEM) from the scanning fixture"
$NW --format cef --min-requests 20 "$FIX/scanning.log"
assert_exit 2

hr "5. NDJSON output (one record per line)"
$NW --format ndjson --min-requests 20 "$FIX/scanning.log"
assert_exit 2

hr "6. Syslog RFC 5424 output"
$NW --format syslog --min-requests 1 "$FIX/badua.log"
assert_exit 2

hr "7. Real-time tail (--follow --once) against a fixture"
$NW --follow "$FIX/scanning.log" --once --min-requests 20
assert_exit 2

hr "8. Analytics summary on a clean log (no findings -> exit 0)"
$NW --top 5 "$FIX/combined.log"
assert_exit 0

hr "9. Upstream latency percentiles (p50/p95) + upstream error rate"
$NW "$FIX/upstream.log"
assert_exit 0

hr "10. X-Forwarded-For attribution (--xff trusts originating client)"
$NW --xff --min-requests 1 "$FIX/xff.log"
assert_exit 2

hr "11. Parse-error handling (malformed lines counted, valid line kept)"
$NW "$FIX/malformed.log"
assert_exit 0

hr "12. stdin pipe mode"
cat sample.log | $NW -
assert_exit 2

printf '\n---------------------------------------------\n'
if [ "$fails" -eq 0 ]; then
  printf 'ALL DEMOS PASSED\n'
  exit 0
else
  printf '%s DEMO(S) FAILED\n' "$fails"
  exit 1
fi
