#!/usr/bin/env lua
-- Self-contained test harness for nginxwatch. No external dependencies.
-- Run: lua tests/run.lua   (from repo root; exits nonzero on any failure)

-- make the module importable regardless of CWD
package.path = "./?.lua;" .. package.path
local nw = require("nginxwatch")

local passed, failed = 0, 0
local failures = {}

local function check(cond, name, detail)
  if cond then
    passed = passed + 1
    io.write("  ok   " .. name .. "\n")
  else
    failed = failed + 1
    failures[#failures + 1] = name .. (detail and ("  -- " .. detail) or "")
    io.write("  FAIL " .. name .. (detail and ("  -- " .. detail) or "") .. "\n")
  end
end

local function eq(a, b, name)
  check(a == b, name, string.format("expected %s got %s", tostring(b), tostring(a)))
end

-- fixture path helper: tests may run from repo root
local FIX = "tests/fixtures/"

local function read_lines(path)
  local fh = assert(io.open(path, "r"), "cannot open " .. path)
  local lines = {}
  for l in fh:lines() do lines[#lines + 1] = l end
  fh:close()
  return lines
end

local function iter_from(lines)
  local i = 0
  return function() i = i + 1; return lines[i] end
end

local function process_file(path, opt)
  return nw.process_lines(iter_from(read_lines(path)), opt or {})
end

local function find_type(findings, t)
  local out = {}
  for _, f in ipairs(findings) do if f.type == t then out[#out + 1] = f end end
  return out
end

--------------------------------------------------------------------------------
io.write("== parsing ==\n")
--------------------------------------------------------------------------------
do
  local r = nw.parse_line('192.0.2.10 - alice [22/Jun/2026:12:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "https://ref/" "Mozilla/5.0"')
  check(r ~= nil, "combined parses")
  eq(r.ip, "192.0.2.10", "combined ip")
  eq(r.method, "GET", "combined method")
  eq(r.path, "/index.html", "combined path")
  eq(r.status, 200, "combined status")
  eq(r.bytes, 512, "combined bytes")
  eq(r.ua, "Mozilla/5.0", "combined ua")
  eq(r.referer, "https://ref/", "combined referer")
  check(r.epoch ~= nil, "combined time parsed")
end

do
  local r = nw.parse_line('192.0.2.20 - - [22/Jun/2026:12:05:01 +0000] "GET /home HTTP/1.1" 200 1024')
  check(r ~= nil, "common parses")
  eq(r.status, 200, "common status")
  eq(r.bytes, 1024, "common bytes")
  eq(r.ua, nil, "common has no ua")
end

do
  local r = nw.parse_line('2001:db8:85a3::8a2e:370:7334 - - [22/Jun/2026:12:10:01 +0000] "GET / HTTP/1.1" 200 320 "-" "UA"')
  check(r ~= nil, "ipv6 parses")
  eq(r.ip, "2001:db8:85a3::8a2e:370:7334", "ipv6 address")
end

do
  local r = nw.parse_line('10.0.0.1 - - [22/Jun/2026:20:00:01 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" xff=70.70.70.70, 10.0.0.1', { xff = true })
  eq(r.ip, "70.70.70.70", "xff last hop trusted")
  local r2 = nw.parse_line('10.0.0.1 - - [22/Jun/2026:20:00:01 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" xff=70.70.70.70, 10.0.0.1')
  eq(r2.ip, "10.0.0.1", "xff ignored without opt")
end

do
  -- missing referer/ua tolerated (dash)
  local r = nw.parse_line('192.0.2.5 - - [22/Jun/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 10 "-" "-"')
  eq(r.ua, "-", "dash ua kept as-is")
  -- malformed request line kept as path
  local r2 = nw.parse_line('192.0.2.5 - - [22/Jun/2026:12:00:01 +0000] "GET" 400 0 "-" "-"')
  check(r2 ~= nil, "malformed request still parses status")
  eq(r2.status, 400, "malformed status")
end

do
  local r, err = nw.parse_line("this is not a log line at all")
  check(r == nil, "garbage line rejected")
  check(err ~= nil, "garbage line reports error")
end

do
  local r = nw.parse_line('10.1.1.1 - - [22/Jun/2026:19:00:02 +0000] "GET /b HTTP/1.1" 200 100 "-" "UA" 0.050 0.045')
  eq(r.upstream_time, 0.045, "upstream_response_time parsed")
  eq(r.request_time, 0.050, "request_time parsed")
end

do
  -- timezone normalization: +0000 vs -0100 should differ by 3600s
  local a = nw.parse_time("22/Jun/2026:12:00:00 +0000")
  local b = nw.parse_time("22/Jun/2026:12:00:00 -0100")
  eq(b - a, 3600, "timezone offset normalized to UTC")
end

--------------------------------------------------------------------------------
io.write("== detectors ==\n")
--------------------------------------------------------------------------------
do
  local _, findings = process_file(FIX .. "scanning.log", { min_requests = 20, ratio_404 = 0.4, enum_threshold = 15 })
  check(#find_type(findings, "scanning") == 1, "scanning detected")
  check(#find_type(findings, "enumeration") == 1, "enumeration detected")
  local s = find_type(findings, "scanning")[1]
  check(s.ratio_404 >= 0.4, "scanning ratio over threshold")
  eq(s.severity, "high", "scanning severity high")
end

do
  local _, findings = process_file(FIX .. "flooding.log", { min_requests = 20, rate = 120 })
  check(#find_type(findings, "flooding") == 1, "flooding detected")
  check(#find_type(findings, "rate_spike") == 1, "rate_spike detected")
  eq(find_type(findings, "rate_spike")[1].peak_rpm, 150, "rate_spike peak rpm")
end

do
  local _, findings = process_file(FIX .. "probing.log", { min_requests = 20 })
  local p = find_type(findings, "probing")
  check(#p == 1, "probing detected")
  check(p[1].sensitive_hits >= 5, "probing counts sensitive hits")
  eq(p[1].severity, "high", "probing severity high (>=5 hits)")
end

do
  local _, findings = process_file(FIX .. "badua.log", { min_requests = 1 })
  local b = find_type(findings, "bad_user_agent")
  check(#b >= 1, "sqlmap UA detected")
  eq(b[1].signature, "sqlmap", "bad ua signature = sqlmap")
end

do
  local _, findings = process_file(FIX .. "emptyua.log", { min_requests = 5 })
  local b = find_type(findings, "bad_user_agent")
  check(#b == 1, "empty UA flood detected")
  eq(b[1].signature, "(empty)", "empty ua signature")
end

do
  local _, findings = process_file(FIX .. "errorburst.log", { min_requests = 1, err_burst = 20 })
  check(#find_type(findings, "error_burst") == 1, "5xx error burst detected")
  eq(find_type(findings, "error_burst")[1].server_errors, 25, "error burst count")
end

do
  local _, findings = process_file(FIX .. "large.log", { min_requests = 1, large_bytes = 10485760 })
  check(#find_type(findings, "large_response") == 1, "large response detected")
end

--------------------------------------------------------------------------------
io.write("== analytics / summary ==\n")
--------------------------------------------------------------------------------
do
  local summary = process_file(FIX .. "upstream.log", {})
  check(summary.upstream ~= nil, "upstream latency summarized")
  check(summary.upstream.p95 ~= nil, "p95 present")
  check(summary.upstream.error_rate > 0, "upstream error rate computed")
  eq(summary.upstream.samples, 4, "upstream sample count")
end

do
  local summary = process_file(FIX .. "combined.log", { top = 5 })
  eq(summary.lines, 3, "combined line count")
  eq(summary.sources, 1, "combined single source")
  eq(summary.status_class["2xx"], 1, "status 2xx count")
  eq(summary.status_class["3xx"], 1, "status 3xx count")
  eq(summary.status_class["4xx"], 1, "status 4xx count")
  check(#summary.top_talkers >= 1, "top talkers present")
  check(#summary.requests_per_minute >= 1, "rpm buckets present")
end

do
  local summary = process_file(FIX .. "malformed.log", {})
  check(summary.parse_errors >= 2, "parse errors counted")
  eq(summary.lines, 1, "only valid line aggregated")
end

--------------------------------------------------------------------------------
io.write("== output encoders ==\n")
--------------------------------------------------------------------------------
do
  local summary, findings = process_file(FIX .. "scanning.log", { min_requests = 20 })
  local jsonout = nw.render("json", summary, findings)
  check(jsonout:find('"tool":"nginxwatch"', 1, true) ~= nil, "json has tool field")
  check(jsonout:find('"findings"', 1, true) ~= nil, "json has findings array")
  check(jsonout:find('"type":"scanning"', 1, true) ~= nil, "json contains scanning finding")

  local nd = nw.render("ndjson", summary, findings)
  local nlines = select(2, nd:gsub("\n", "\n"))
  check(nlines >= 2, "ndjson emits multiple lines")
  check(nd:find('"record":"summary"', 1, true) ~= nil, "ndjson summary line")
  check(nd:find('"record":"finding"', 1, true) ~= nil, "ndjson finding line")

  local cef = nw.render("cef", summary, findings)
  check(cef:find("CEF:0|Cognis Digital|nginxwatch|", 1, true) ~= nil, "cef header")
  check(cef:find("src=", 1, true) ~= nil, "cef has src extension")

  local sl = nw.render("syslog", summary, findings)
  check(sl:find("nginxwatch@0", 1, true) ~= nil, "syslog structured data")
  check(sl:match("^<%d+>1 ") ~= nil, "syslog RFC5424 PRI+version")
end

do
  -- JSON escaping correctness (embedded quotes / backslashes)
  local enc = nw.json.encode({ msg = 'he said "hi"\\path', n = 5, arr = nw.json.as_array({1,2}) })
  check(enc:find('\\"hi\\"', 1, true) ~= nil, "json escapes quotes")
  check(enc:find('\\\\path', 1, true) ~= nil, "json escapes backslash")
end

--------------------------------------------------------------------------------
io.write("== thresholds tuning ==\n")
--------------------------------------------------------------------------------
do
  -- with impossible thresholds nothing fires
  local _, findings = process_file(FIX .. "scanning.log", { min_requests = 100000, enum_threshold = 100000, ratio_404 = 1.1 })
  check(#find_type(findings, "scanning") == 0, "raising thresholds suppresses scanning")
  check(#find_type(findings, "enumeration") == 0, "raising thresholds suppresses enumeration")
end

--------------------------------------------------------------------------------
io.write("== tail / follow (--once) ==\n")
--------------------------------------------------------------------------------
do
  local emitted = {}
  local summary, findings = nw.follow(FIX .. "scanning.log",
    { once = true, min_requests = 20, enum_threshold = 15 },
    function(f) emitted[#emitted + 1] = f end)
  check(summary ~= nil, "follow --once returns summary")
  check(#emitted >= 1, "follow --once emitted findings incrementally")
  check(#find_type(findings, "scanning") == 1, "follow --once final findings correct")
end

do
  -- max_lines guard terminates without hanging
  local summary = nw.follow(FIX .. "flooding.log",
    { max_lines = 10, max_iterations = 0 }, nil)
  check(summary ~= nil, "follow max-lines guard terminates")
  eq(summary.lines, 10, "follow max-lines respected")
end

--------------------------------------------------------------------------------
io.write("\n")
io.write(string.format("%d passed, %d failed\n", passed, failed))
if failed > 0 then
  io.write("FAILURES:\n")
  for _, f in ipairs(failures) do io.write("  - " .. f .. "\n") end
  os.exit(1)
end
os.exit(0)
