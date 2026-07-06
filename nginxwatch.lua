#!/usr/bin/env lua
-- nginxwatch — nginx/Apache access-log watcher & anomaly detector (Lua 5.x)
-- Part of the Cognis Neural Suite. Single-purpose, machine-readable output, CI-tested.
--
-- Parses nginx/Apache "combined" and "common" access-log formats (plus an
-- optional nginx upstream-timing format) and detects, per source IP:
--   scanning        high 404 ratio (content discovery / fuzzing)
--   probing         requests to sensitive paths (.env, wp-login, /admin, .git, ...)
--   enumeration     many DISTINCT 404 paths (directory/endpoint brute force)
--   flooding        request volume above a threshold
--   rate_spike      requests/minute over a window above --rate
--   bad_user_agent  known scanner UAs (sqlmap/nikto/nmap/masscan) or empty UA
--   error_burst     5xx spikes concentrated on one source
--   large_response  unusually large response bytes (exfil hint)
--
-- Also emits an analytics summary: top talkers, status class distribution,
-- top paths, top user-agents, requests-per-minute buckets, and (when the log
-- carries $upstream_response_time) p50/p95 latency + upstream error rate.
--
-- Output formats: json (default), ndjson, cef (ArcSight), syslog (RFC 5424).
-- Exit code: 2 when findings exist, 0 when clean, 1 on error.
--
-- This module is also require()-able: `local nw = require("nginxwatch")`
-- exposes the parser, detector, and encoders for testing/embedding.

local M = {}

--------------------------------------------------------------------------------
-- Version
--------------------------------------------------------------------------------
M.VERSION = "1.0.0"

--------------------------------------------------------------------------------
-- Sensitive path signatures (Lua patterns, matched against lowercased path)
--------------------------------------------------------------------------------
M.SENSITIVE = {
  "%.env", "%.env%.", "wp%-login", "wp%-admin", "xmlrpc%.php", "/admin",
  "%.git", "/%.svn", "/%.hg", "/phpmyadmin", "/pma/", "/adminer",
  "/%.aws", "/%.ssh", "id_rsa", "/actuator", "/config%.", "/configuration",
  "/%.docker", "docker%-compose", "/%.htpasswd", "/%.htaccess", "/server%-status",
  "/manager/html", "/jenkins", "/solr/", "/console", "/debug",
  "/wp%-config", "/backup", "%.sql", "%.bak", "%.old", "/%.well%-known/security",
  "/vendor/phpunit", "/cgi%-bin/", "/boaform", "/hnap1", "/%.vscode",
  "/telescope", "/graphql", "/api/v%d+/users", "/%.npmrc", "/%.dockerignore",
}

--------------------------------------------------------------------------------
-- Suspicious user-agent signatures (matched against lowercased UA)
--------------------------------------------------------------------------------
M.BAD_UA = {
  "sqlmap", "nikto", "nmap", "masscan", "zgrab", "zmap", "nessus", "openvas",
  "acunetix", "netsparker", "wpscan", "dirbuster", "gobuster", "feroxbuster",
  "ffuf", "hydra", "metasploit", "havij", "arachni", "w3af", "skipfish",
  "burp", "nuclei", "whatweb", "commix", "xsser", "joomscan", "droopescan",
}

--------------------------------------------------------------------------------
-- Minimal, correct JSON encoder (handles escaping; avoids hand string-concat)
--------------------------------------------------------------------------------
local json = {}
local escape_map = {
  ['"'] = '\\"', ['\\'] = '\\\\', ['\b'] = '\\b', ['\f'] = '\\f',
  ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t',
}
local function esc_char(c)
  return escape_map[c] or string.format("\\u%04x", string.byte(c))
end
local function json_string(s)
  return '"' .. tostring(s):gsub('[%z\1-\31\\"]', esc_char) .. '"'
end

-- Marker so callers can force array vs object for empty tables.
json.array_mt = {}
function json.as_array(t) return setmetatable(t or {}, json.array_mt) end

local function is_array(t)
  if getmetatable(t) == json.array_mt then return true end
  local n = 0
  for k in pairs(t) do
    if type(k) ~= "number" then return false end
    n = n + 1
  end
  return n > 0 and n == #t
end

local function encode_value(v, out)
  local tv = type(v)
  if v == nil then
    out[#out + 1] = "null"
  elseif tv == "number" then
    if v ~= v then out[#out + 1] = "null"           -- NaN
    elseif v == math.huge then out[#out + 1] = "null"
    elseif v == -math.huge then out[#out + 1] = "null"
    elseif math.type and math.type(v) == "integer" then
      out[#out + 1] = string.format("%d", v)
    elseif v == math.floor(v) and math.abs(v) < 1e15 then
      out[#out + 1] = string.format("%d", v)
    else
      out[#out + 1] = string.format("%.6g", v)
    end
  elseif tv == "boolean" then
    out[#out + 1] = v and "true" or "false"
  elseif tv == "string" then
    out[#out + 1] = json_string(v)
  elseif tv == "table" then
    if is_array(v) then
      out[#out + 1] = "["
      for i = 1, #v do
        if i > 1 then out[#out + 1] = "," end
        encode_value(v[i], out)
      end
      out[#out + 1] = "]"
    else
      -- object with stable (sorted) key order for reproducible output
      local keys = {}
      for k in pairs(v) do keys[#keys + 1] = k end
      table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
      out[#out + 1] = "{"
      for i = 1, #keys do
        if i > 1 then out[#out + 1] = "," end
        out[#out + 1] = json_string(tostring(keys[i]))
        out[#out + 1] = ":"
        encode_value(v[keys[i]], out)
      end
      out[#out + 1] = "}"
    end
  else
    out[#out + 1] = json_string(tostring(v))
  end
end

function json.encode(v)
  local out = {}
  encode_value(v, out)
  return table.concat(out)
end
M.json = json

--------------------------------------------------------------------------------
-- Timestamp parsing: nginx/Apache common time  [10/Oct/2000:13:55:36 -0700]
-- Returns epoch seconds (UTC) or nil.
--------------------------------------------------------------------------------
local MONTHS = {
  Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
  Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12,
}

-- days from civil (Howard Hinnant's algorithm) -> avoids os.time/tz drift
local function days_from_civil(y, m, d)
  y = (m <= 2) and (y - 1) or y
  local era = (y >= 0 and y or y - 399) // 400
  local yoe = y - era * 400
  local doy = (153 * ((m > 2) and (m - 3) or (m + 9)) + 2) // 5 + d - 1
  local doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
  return era * 146097 + doe - 719468
end

function M.parse_time(str)
  if not str then return nil end
  local d, mon, y, hh, mm, ss, sign, tzh, tzm =
    str:match("(%d+)/(%a+)/(%d+):(%d+):(%d+):(%d+)%s*([%+%-]?)(%d?%d?)(%d?%d?)")
  if not d then return nil end
  local month = MONTHS[mon]
  if not month then return nil end
  local days = days_from_civil(tonumber(y), month, tonumber(d))
  local secs = days * 86400 + tonumber(hh) * 3600 + tonumber(mm) * 60 + tonumber(ss)
  -- apply timezone offset to normalize to UTC
  if sign ~= "" and tzh ~= "" then
    local off = (tonumber(tzh) or 0) * 3600 + (tonumber(tzm) or 0) * 60
    if sign == "+" then secs = secs - off else secs = secs + off end
  end
  return secs
end

--------------------------------------------------------------------------------
-- Line parser. Supports:
--   combined : IP - user [time] "METHOD path proto" status bytes "ref" "ua"
--   common   : IP - user [time] "METHOD path proto" status bytes
--   upstream : combined + trailing rt=<request_time> urt=<upstream_response_time>
--              (nginx log_format with $request_time / $upstream_response_time
--               appended as space-separated fields; also parses bare trailing
--               numeric fields)
-- Tolerates missing referer/UA, missing bytes ("-"), IPv6 remote addr.
-- With opt.xff = true, if an X-Forwarded-For value is present as a trailing
-- quoted field or an "xff=" tag, the originating (leftmost) client IP is used.
--------------------------------------------------------------------------------

-- Extract the request line fields; returns method, path, proto (any may be nil)
local function split_request(req)
  if not req or req == "" or req == "-" then return nil, nil, nil end
  local method, path, proto = req:match("^(%S+)%s+(%S+)%s+(%S+)$")
  if not method then
    method, path = req:match("^(%S+)%s+(%S+)$")
  end
  if not method then
    path = req            -- malformed request line; keep raw as path
  end
  return method, path, proto
end

-- Grab the bracketed time, the quoted request, and everything after.
function M.parse_line(line, opt)
  opt = opt or {}
  if not line or line == "" then return nil, "empty" end

  -- remote addr is first whitespace-delimited token (IPv4 or IPv6)
  local ip = line:match("^(%S+)")
  if not ip then return nil, "no_ip" end

  local time_str = line:match("%[([^%]]+)%]")
  local req = line:match('"([^"]*)"')      -- first quoted field = request line

  -- status + bytes follow the closing quote of the request
  local after = line:match('"[^"]*"%s+(.*)$')
  local status, bytes
  local rest = after
  if after then
    status, bytes, rest = after:match("^(%d%d%d)%s+(%S+)%s*(.*)$")
    if not status then
      status = after:match("^(%d%d%d)")
      rest = after:gsub("^%d%d%d%s*", "")
    end
  end

  -- referer + user-agent are the next two quoted fields in combined format
  local referer, ua
  if rest then
    local q1, q2 = rest:match('^"([^"]*)"%s+"([^"]*)"')
    if q1 then referer, ua = q1, q2 else
      referer = rest:match('^"([^"]*)"')
    end
  end

  -- upstream / request timing: look for rt=/urt= tags or trailing bare floats
  local request_time = tonumber(rest and rest:match("rt=([%d%.]+)"))
  local upstream_time = tonumber(rest and rest:match("urt=([%d%.]+)"))
  if not upstream_time and rest then
    -- nginx often appends: ... "ua" <request_time> <upstream_response_time>
    local a, b = rest:match('"[^"]*"%s+([%d%.]+)%s+([%d%.]+)%s*$')
    if a then request_time = tonumber(a); upstream_time = tonumber(b) end
    if not upstream_time then
      local one = rest:match('"[^"]*"%s+([%d%.]+)%s*$')
      if one then request_time = tonumber(one) end
    end
  end

  -- X-Forwarded-For handling (optional): trust last hop
  if opt.xff then
    local xff = line:match("xff=([%d%.:a-fA-F, ]+)")
    if not xff then
      -- some formats append XFF as the last quoted field
      local last
      for q in line:gmatch('"([^"]*)"') do last = q end
      if last and last:match("^[%d%.:%s,]+$") and last ~= "-" then xff = last end
    end
    if xff and xff ~= "-" then
      -- X-Forwarded-For is "client, proxy1, proxy2, ..."; the ORIGINATING
      -- client is the leftmost entry. That is the attribution-relevant source,
      -- so we trust the first hop. (Only safe when your edge overwrites XFF;
      -- see docs/DETECTIONS.md for the trusted-proxy caveat.)
      local hop = xff:match("^%s*([^,%s]+)")
      if hop then ip = hop end
    end
  end

  if not status then
    -- Line had an IP but no parseable status: treat as parse error unless it's
    -- clearly a request we can still bucket. Be strict to surface bad formats.
    return nil, "no_status"
  end

  local method, path, proto = split_request(req)

  return {
    ip = ip,
    time_str = time_str,
    epoch = M.parse_time(time_str),
    method = method,
    path = path,
    proto = proto,
    status = tonumber(status),
    bytes = (bytes and bytes ~= "-") and tonumber(bytes) or 0,
    referer = referer,
    ua = ua,
    request_time = request_time,
    upstream_time = upstream_time,
  }
end

--------------------------------------------------------------------------------
-- Aggregator: accumulate per-IP and global stats from parsed records.
--------------------------------------------------------------------------------
function M.new_aggregator(opt)
  opt = opt or {}
  return {
    opt = opt,
    ips = {},               -- ip -> stats
    total_lines = 0,        -- successfully parsed
    parse_errors = 0,
    parse_error_samples = {},
    status_class = { ["2xx"] = 0, ["3xx"] = 0, ["4xx"] = 0, ["5xx"] = 0, other = 0 },
    paths = {},             -- path -> count
    uas = {},               -- ua -> count
    minute_buckets = {},    -- epoch_minute -> count
    upstream_times = {},    -- list of upstream_time samples
    upstream_errors = 0,    -- 5xx count when upstream timing present
    upstream_total = 0,
    bytes_samples = {},     -- for large-response detection (running)
  }
end

local function ip_stat(agg, ip)
  local s = agg.ips[ip]
  if not s then
    s = {
      total = 0, c404 = 0, c5xx = 0,
      sensitive = 0, sensitive_paths = {},
      distinct_404 = {}, distinct_404_count = 0,
      minute = {}, max_per_min = 0,
      bad_ua = false, bad_ua_name = nil, empty_ua = 0,
      max_bytes = 0, max_bytes_path = nil,
      first_epoch = nil, last_epoch = nil,
    }
    agg.ips[ip] = s
  end
  return s
end

function M.aggregate(agg, rec)
  if not rec then return end
  agg.total_lines = agg.total_lines + 1
  local s = ip_stat(agg, rec.ip)
  s.total = s.total + 1

  -- status class
  local st = rec.status or 0
  if st >= 200 and st < 300 then agg.status_class["2xx"] = agg.status_class["2xx"] + 1
  elseif st >= 300 and st < 400 then agg.status_class["3xx"] = agg.status_class["3xx"] + 1
  elseif st >= 400 and st < 500 then agg.status_class["4xx"] = agg.status_class["4xx"] + 1
  elseif st >= 500 and st < 600 then agg.status_class["5xx"] = agg.status_class["5xx"] + 1
  else agg.status_class.other = agg.status_class.other + 1 end

  if st == 404 then
    s.c404 = s.c404 + 1
    if rec.path and not s.distinct_404[rec.path] then
      s.distinct_404[rec.path] = true
      s.distinct_404_count = s.distinct_404_count + 1
    end
  end
  if st >= 500 and st < 600 then s.c5xx = s.c5xx + 1 end

  -- sensitive path probing
  if rec.path then
    local lp = rec.path:lower()
    for _, pat in ipairs(M.SENSITIVE) do
      if lp:find(pat) then
        s.sensitive = s.sensitive + 1
        if not s.sensitive_paths[rec.path] then s.sensitive_paths[rec.path] = 0 end
        s.sensitive_paths[rec.path] = s.sensitive_paths[rec.path] + 1
        break
      end
    end
    agg.paths[rec.path] = (agg.paths[rec.path] or 0) + 1
  end

  -- user agent
  local ua = rec.ua
  if ua == nil or ua == "" or ua == "-" then
    s.empty_ua = s.empty_ua + 1
    agg.uas["(empty)"] = (agg.uas["(empty)"] or 0) + 1
  else
    agg.uas[ua] = (agg.uas[ua] or 0) + 1
    local lua_ua = ua:lower()
    for _, sig in ipairs(M.BAD_UA) do
      if lua_ua:find(sig, 1, true) then
        s.bad_ua = true
        s.bad_ua_name = sig
        break
      end
    end
  end

  -- bytes / large response
  local b = rec.bytes or 0
  if b > s.max_bytes then s.max_bytes = b; s.max_bytes_path = rec.path end
  agg.bytes_samples[#agg.bytes_samples + 1] = b

  -- time buckets (global + per-ip per-minute)
  if rec.epoch then
    local minute = rec.epoch - (rec.epoch % 60)
    agg.minute_buckets[minute] = (agg.minute_buckets[minute] or 0) + 1
    s.minute[minute] = (s.minute[minute] or 0) + 1
    if s.minute[minute] > s.max_per_min then s.max_per_min = s.minute[minute] end
    if not s.first_epoch or rec.epoch < s.first_epoch then s.first_epoch = rec.epoch end
    if not s.last_epoch or rec.epoch > s.last_epoch then s.last_epoch = rec.epoch end
  end

  -- upstream timing
  if rec.upstream_time then
    agg.upstream_times[#agg.upstream_times + 1] = rec.upstream_time
    agg.upstream_total = agg.upstream_total + 1
    if st >= 500 and st < 600 then agg.upstream_errors = agg.upstream_errors + 1 end
  end
end

--------------------------------------------------------------------------------
-- Detection engine. Returns a list of findings (tables) sorted deterministically.
--------------------------------------------------------------------------------
local SEVERITY_RANK = { info = 1, low = 2, medium = 3, high = 4, critical = 5 }

function M.detect(agg)
  local opt = agg.opt
  local min_requests = opt.min_requests or 20
  local ratio_404 = opt.ratio_404 or 0.4
  local rate = opt.rate or 120                 -- req/min flood threshold
  local enum_threshold = opt.enum_threshold or 15
  local large_bytes = opt.large_bytes or 10485760  -- 10 MiB
  local err_burst = opt.err_burst or 20

  local findings = {}
  local function add(f) findings[#findings + 1] = f end

  for ip, s in pairs(agg.ips) do
    -- scanning: high 404 ratio among IPs with enough volume
    if s.total >= min_requests then
      local r = s.c404 / s.total
      if r >= ratio_404 then
        add({
          type = "scanning", ip = ip, severity = "high",
          requests = s.total, not_found = s.c404, ratio_404 = r,
          evidence = string.format("%d/%d requests returned 404 (%.1f%%)",
            s.c404, s.total, r * 100),
        })
      end
    end

    -- enumeration: many DISTINCT 404 paths (even below scanning ratio)
    if s.distinct_404_count >= enum_threshold then
      add({
        type = "enumeration", ip = ip, severity = "high",
        distinct_404_paths = s.distinct_404_count, requests = s.total,
        evidence = string.format("%d distinct 404 paths (endpoint brute force)",
          s.distinct_404_count),
      })
    end

    -- probing: any sensitive-path hit
    if s.sensitive > 0 then
      local top = {}
      for p, c in pairs(s.sensitive_paths) do top[#top + 1] = { path = p, count = c } end
      table.sort(top, function(a, b) return a.count > b.count end)
      local sample = {}
      for i = 1, math.min(5, #top) do sample[i] = top[i].path end
      add({
        type = "probing", ip = ip,
        severity = s.sensitive >= 5 and "high" or "medium",
        sensitive_hits = s.sensitive,
        paths = json.as_array(sample),
        evidence = string.format("%d requests to sensitive paths", s.sensitive),
      })
    end

    -- flooding: volume well above baseline
    if s.total >= (min_requests * 5) then
      add({
        type = "flooding", ip = ip, severity = "medium",
        requests = s.total,
        evidence = string.format("%d total requests (>= %d)", s.total, min_requests * 5),
      })
    end

    -- rate_spike: peak requests/minute over the rate threshold
    if s.max_per_min >= rate then
      add({
        type = "rate_spike", ip = ip, severity = "high",
        peak_rpm = s.max_per_min, threshold_rpm = rate,
        evidence = string.format("peak %d req/min (threshold %d)", s.max_per_min, rate),
      })
    end

    -- bad_user_agent: known scanner UA or heavy empty-UA usage
    if s.bad_ua then
      add({
        type = "bad_user_agent", ip = ip, severity = "high",
        signature = s.bad_ua_name, requests = s.total,
        evidence = string.format("user-agent matched scanner signature '%s'", s.bad_ua_name),
      })
    elseif s.empty_ua >= min_requests and s.empty_ua == s.total then
      add({
        type = "bad_user_agent", ip = ip, severity = "low",
        signature = "(empty)", requests = s.empty_ua,
        evidence = string.format("%d requests with empty user-agent", s.empty_ua),
      })
    end

    -- error_burst: many 5xx from one source (possible attack against upstream)
    if s.c5xx >= err_burst then
      add({
        type = "error_burst", ip = ip, severity = "medium",
        server_errors = s.c5xx, requests = s.total,
        evidence = string.format("%d 5xx responses (upstream stress)", s.c5xx),
      })
    end

    -- large_response: unusually large bytes served (exfil hint)
    if s.max_bytes >= large_bytes then
      add({
        type = "large_response", ip = ip, severity = "low",
        max_bytes = s.max_bytes, path = s.max_bytes_path,
        evidence = string.format("response of %d bytes to %s",
          s.max_bytes, tostring(s.max_bytes_path)),
      })
    end
  end

  -- deterministic ordering: severity desc, then type, then ip
  table.sort(findings, function(a, b)
    local ra, rb = SEVERITY_RANK[a.severity] or 0, SEVERITY_RANK[b.severity] or 0
    if ra ~= rb then return ra > rb end
    if a.type ~= b.type then return a.type < b.type end
    return tostring(a.ip) < tostring(b.ip)
  end)

  return findings
end

--------------------------------------------------------------------------------
-- Analytics summary
--------------------------------------------------------------------------------
local function top_n(map, n, key_name, val_name)
  local t = {}
  for k, v in pairs(map) do t[#t + 1] = { k = k, v = v } end
  table.sort(t, function(a, b)
    if a.v ~= b.v then return a.v > b.v end
    return tostring(a.k) < tostring(b.k)
  end)
  local out = json.as_array({})
  for i = 1, math.min(n, #t) do
    local e = {}
    e[key_name] = t[i].k
    e[val_name] = t[i].v
    out[i] = e
  end
  return out
end

local function percentile(sorted, p)
  if #sorted == 0 then return nil end
  local idx = math.ceil(p * #sorted)
  if idx < 1 then idx = 1 end
  if idx > #sorted then idx = #sorted end
  return sorted[idx]
end

function M.summarize(agg)
  local opt = agg.opt
  local n = opt.top or 10

  local nips = 0
  for _ in pairs(agg.ips) do nips = nips + 1 end

  local talkers_map = {}
  for ip, s in pairs(agg.ips) do talkers_map[ip] = s.total end

  local summary = {
    tool = "nginxwatch",
    version = M.VERSION,
    lines = agg.total_lines,
    parse_errors = agg.parse_errors,
    sources = nips,
    status_class = agg.status_class,
    top_talkers = top_n(talkers_map, n, "ip", "requests"),
    top_paths = top_n(agg.paths, n, "path", "requests"),
    top_user_agents = top_n(agg.uas, n, "user_agent", "requests"),
  }

  -- requests per minute (sorted by time)
  local rpm = {}
  for minute, count in pairs(agg.minute_buckets) do
    rpm[#rpm + 1] = { minute = minute, requests = count }
  end
  table.sort(rpm, function(a, b) return a.minute < b.minute end)
  summary.requests_per_minute = json.as_array(rpm)

  -- upstream latency
  if agg.upstream_total > 0 then
    local sorted = {}
    for i = 1, #agg.upstream_times do sorted[i] = agg.upstream_times[i] end
    table.sort(sorted)
    summary.upstream = {
      samples = agg.upstream_total,
      p50 = percentile(sorted, 0.50),
      p95 = percentile(sorted, 0.95),
      max = sorted[#sorted],
      error_rate = agg.upstream_errors / agg.upstream_total,
    }
  end

  return summary
end

--------------------------------------------------------------------------------
-- Output encoders
--------------------------------------------------------------------------------
local encoders = {}

-- JSON: full report object with summary + findings
function encoders.json(summary, findings)
  local report = {}
  for k, v in pairs(summary) do report[k] = v end
  report.findings = json.as_array(findings)
  return json.encode(report) .. "\n"
end

-- NDJSON: one JSON object per line. First line = summary, rest = findings.
function encoders.ndjson(summary, findings)
  local out = {}
  local s = {}
  for k, v in pairs(summary) do s[k] = v end
  s.record = "summary"
  out[#out + 1] = json.encode(s)
  for _, f in ipairs(findings) do
    local rec = {}
    for k, v in pairs(f) do rec[k] = v end
    rec.record = "finding"
    out[#out + 1] = json.encode(rec)
  end
  return table.concat(out, "\n") .. "\n"
end

-- CEF (ArcSight Common Event Format):
-- CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
local CEF_SEV = { info = 1, low = 3, medium = 5, high = 8, critical = 10 }
local function cef_escape_header(s)
  return tostring(s):gsub("\\", "\\\\"):gsub("|", "\\|")
end
local function cef_escape_ext(s)
  return tostring(s):gsub("\\", "\\\\"):gsub("=", "\\="):gsub("\n", "\\n")
end
function encoders.cef(_summary, findings)
  local out = {}
  for _, f in ipairs(findings) do
    local ext = {}
    ext[#ext + 1] = "src=" .. cef_escape_ext(f.ip)
    ext[#ext + 1] = "cs1Label=evidence"
    ext[#ext + 1] = "cs1=" .. cef_escape_ext(f.evidence or "")
    if f.requests then ext[#ext + 1] = "cnt=" .. tostring(f.requests) end
    if f.ratio_404 then ext[#ext + 1] = "cs2Label=ratio404 cs2=" .. string.format("%.3f", f.ratio_404) end
    if f.peak_rpm then ext[#ext + 1] = "cn1Label=peakRpm cn1=" .. tostring(f.peak_rpm) end
    if f.signature then ext[#ext + 1] = "cs3Label=signature cs3=" .. cef_escape_ext(f.signature) end
    local line = string.format(
      "CEF:0|Cognis Digital|nginxwatch|%s|%s|%s|%d|%s",
      M.VERSION,
      cef_escape_header(f.type),
      cef_escape_header(f.type .. " from " .. f.ip),
      CEF_SEV[f.severity] or 3,
      table.concat(ext, " "))
    out[#out + 1] = line
  end
  return table.concat(out, "\n") .. (#out > 0 and "\n" or "")
end

-- Syslog RFC 5424:
-- <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
function encoders.syslog(_summary, findings)
  local out = {}
  -- facility 4 (security/auth), we vary severity per finding; PRI = fac*8 + sev
  local SYSLOG_SEV = { info = 6, low = 5, medium = 4, high = 3, critical = 2 }
  for _, f in ipairs(findings) do
    local sev = SYSLOG_SEV[f.severity] or 5
    local pri = 4 * 8 + sev
    local sd = string.format('[nginxwatch@0 type="%s" src="%s" severity="%s"]',
      f.type, tostring(f.ip), f.severity or "low")
    local line = string.format(
      "<%d>1 - nginxwatch nginxwatch - %s %s %s",
      pri, f.type, sd, f.evidence or "")
    out[#out + 1] = line
  end
  return table.concat(out, "\n") .. (#out > 0 and "\n" or "")
end

M.encoders = encoders

function M.render(fmt, summary, findings)
  local enc = encoders[fmt or "json"]
  if not enc then error("unknown format: " .. tostring(fmt)) end
  return enc(summary, findings)
end

--------------------------------------------------------------------------------
-- High-level: process a set of lines (iterator) into (summary, findings).
--------------------------------------------------------------------------------
function M.process_lines(iter, opt)
  local agg = M.new_aggregator(opt)
  for line in iter do
    local rec, err = M.parse_line(line, opt)
    if rec then
      M.aggregate(agg, rec)
    elseif err ~= "empty" then
      agg.parse_errors = agg.parse_errors + 1
      if #agg.parse_error_samples < 5 then
        agg.parse_error_samples[#agg.parse_error_samples + 1] = line
      end
    end
  end
  local findings = M.detect(agg)
  local summary = M.summarize(agg)
  return summary, findings, agg
end

--------------------------------------------------------------------------------
-- Real-time tail (--follow). Polls file size; re-reads appended bytes.
-- Terminates when: opt.once (drain then stop), opt.max_lines reached, or
-- opt.max_iterations idle polls with no growth.
-- Calls on_finding(finding) as NEW findings appear (incremental).
--------------------------------------------------------------------------------
function M.follow(path, opt, on_finding)
  opt = opt or {}
  local agg = M.new_aggregator(opt)
  local seen = {}                     -- dedup key -> true
  local lines_read = 0
  local max_lines = opt.max_lines
  local max_idle = opt.max_iterations or (opt.once and 0 or 600)
  local poll = opt.poll or 0.5
  local pos = 0
  local idle = 0

  local function finding_key(f)
    return table.concat({ f.type, tostring(f.ip), tostring(f.severity),
      tostring(f.requests or f.peak_rpm or f.sensitive_hits or "") }, "|")
  end

  local function emit_new()
    local findings = M.detect(agg)
    for _, f in ipairs(findings) do
      local k = finding_key(f)
      if not seen[k] then
        seen[k] = true
        if on_finding then on_finding(f, agg) end
      end
    end
  end

  local function read_from(fh)
    fh:seek("set", pos)
    local grew = false
    for line in fh:lines() do
      grew = true
      lines_read = lines_read + 1
      local rec, err = M.parse_line(line, opt)
      if rec then M.aggregate(agg, rec)
      elseif err ~= "empty" then agg.parse_errors = agg.parse_errors + 1 end
      if max_lines and lines_read >= max_lines then break end
    end
    pos = fh:seek()   -- current position for next poll
    return grew
  end

  while true do
    local fh, err = io.open(path, "r")
    if not fh then return nil, "cannot open " .. path .. ": " .. tostring(err) end
    -- handle truncation/rotation: if file shrank, restart from 0
    local size = fh:seek("end")
    if size < pos then pos = 0 end
    local grew = read_from(fh)
    fh:close()

    if grew then emit_new(); idle = 0 else idle = idle + 1 end

    if opt.once then break end
    if max_lines and lines_read >= max_lines then break end
    if idle >= max_idle then break end

    -- sleep between polls without a hard dependency: portable busy-wait via
    -- os.clock is CPU-bound, so prefer os.execute sleep when available; but to
    -- stay dependency-free and CI-safe, we short-circuit when max_idle is 0.
    if max_idle > 0 then
      -- ignore result; if sleep is unavailable we just poll faster
      os.execute(
        (package.config:sub(1,1) == "\\") and "ping -n 1 -w 1 127.0.0.1 >NUL 2>&1"
        or ("sleep " .. tostring(poll) .. " >/dev/null 2>&1"))
    end
  end

  emit_new()
  local findings = M.detect(agg)
  local summary = M.summarize(agg)
  return summary, findings, agg
end

--------------------------------------------------------------------------------
-- CLI
--------------------------------------------------------------------------------
local USAGE = [[
nginxwatch ]] .. M.VERSION .. [[ — nginx/Apache access-log watcher & anomaly detector

usage: nginxwatch [options] FILE... | -
       nginxwatch --follow FILE [options]

options:
  --min-requests N    only consider IPs with >= N requests   (default 20)
  --404-ratio F       flag scanning when 404 fraction >= F    (default 0.4)
  --rate N            flag rate_spike at >= N req/min          (default 120)
  --window S          time window in seconds for rate calc     (default 60)
  --enum N            flag enumeration at >= N distinct 404s   (default 15)
  --top N             top-N entries in analytics summary       (default 10)
  --xff               trust X-Forwarded-For last hop as client IP
  --format FMT        json | ndjson | cef | syslog             (default json)
  -f, --follow FILE   real-time tail mode (poll for appended lines)
  --once              in --follow mode: drain once and exit (no polling)
  --max-lines N       stop after reading N lines (tail safety guard)
  -h, --help          show this help
  --version           print version

exit: 2 = findings, 0 = clean, 1 = error
]]

function M.main(argv)
  local opt = {
    min_requests = 20, ratio_404 = 0.4, rate = 120, window = 60,
    enum_threshold = 15, top = 10, xff = false, format = "json",
  }
  local files = {}
  local follow_file = nil

  local i = 1
  while i <= #argv do
    local a = argv[i]
    if a == "--min-requests" then i = i + 1; opt.min_requests = tonumber(argv[i]) or opt.min_requests
    elseif a == "--404-ratio" then i = i + 1; opt.ratio_404 = tonumber(argv[i]) or opt.ratio_404
    elseif a == "--rate" then i = i + 1; opt.rate = tonumber(argv[i]) or opt.rate
    elseif a == "--window" then i = i + 1; opt.window = tonumber(argv[i]) or opt.window
    elseif a == "--enum" then i = i + 1; opt.enum_threshold = tonumber(argv[i]) or opt.enum_threshold
    elseif a == "--top" then i = i + 1; opt.top = tonumber(argv[i]) or opt.top
    elseif a == "--xff" then opt.xff = true
    elseif a == "--format" then i = i + 1; opt.format = argv[i] or "json"
    elseif a == "-f" or a == "--follow" then i = i + 1; follow_file = argv[i]
    elseif a == "--once" then opt.once = true
    elseif a == "--max-lines" then i = i + 1; opt.max_lines = tonumber(argv[i])
    elseif a == "--version" then io.write(M.VERSION .. "\n"); return 0
    elseif a == "-h" or a == "--help" then io.write(USAGE); return 0
    else files[#files + 1] = a end
    i = i + 1
  end

  if not encoders[opt.format] then
    io.stderr:write("nginxwatch: unknown --format '" .. tostring(opt.format) .. "'\n")
    return 1
  end

  local summary, findings

  if follow_file then
    if not opt.once and not opt.max_lines and not opt.max_iterations then
      -- default to bounded follow to avoid indefinite hangs in non-tty use
      opt.max_iterations = 600
    end
    local s, f, err = M.follow(follow_file, opt, nil)
    if not s then io.stderr:write("nginxwatch: " .. tostring(f or err) .. "\n"); return 1 end
    summary, findings = s, f
  else
    -- gather an iterator over all input lines
    local sources = {}
    if #files == 0 then
      sources[1] = io.stdin
    else
      for _, ff in ipairs(files) do
        if ff == "-" then sources[#sources + 1] = io.stdin
        else
          local fh, err = io.open(ff, "r")
          if not fh then
            io.stderr:write("nginxwatch: cannot open " .. ff .. ": " .. tostring(err) .. "\n")
            return 1
          end
          sources[#sources + 1] = fh
        end
      end
    end

    local si, cur_iter = 1, nil
    local function next_line()
      while true do
        if not cur_iter then
          if si > #sources then return nil end
          cur_iter = sources[si]:lines()
        end
        local l = cur_iter()
        if l ~= nil then return l end
        cur_iter = nil
        si = si + 1
      end
    end

    summary, findings = M.process_lines(next_line, opt)

    for _, fh in ipairs(sources) do
      if fh ~= io.stdin then fh:close() end
    end
  end

  io.write(M.render(opt.format, summary, findings))
  return (#findings > 0) and 2 or 0
end

--------------------------------------------------------------------------------
-- Entry point: run as script, but stay require()-able for tests.
--------------------------------------------------------------------------------
local function is_main()
  -- When run as `lua nginxwatch.lua`, arg[0] is the script and there is no
  -- enclosing module. When require()'d, `...` is the module name.
  return arg ~= nil and (arg[0] or ""):match("nginxwatch") ~= nil and not package.loaded["nginxwatch"]
end

if is_main() then
  os.exit(M.main(arg))
end

return M
