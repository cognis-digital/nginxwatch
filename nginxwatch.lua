#!/usr/bin/env lua
-- nginxwatch — access-log scanner for web recon / brute force (Lua 5.x)
-- Part of the Cognis Neural Suite. Single-purpose, JSON-out, CI-tested.
--
-- Parses nginx/Apache "combined" access-log lines and flags per-source-IP:
--   * scanning   : high 404 ratio (content discovery / fuzzing)
--   * probing    : requests to sensitive paths (.env, wp-login, /admin, .git)
--   * flooding   : request volume above a threshold
--
-- Usage:
--   nginxwatch /var/log/nginx/access.log
--   cat access.log | nginxwatch -
-- Options:
--   --min-requests N   only consider IPs with >= N requests (default 20)
--   --404-ratio F      flag scanning when 404 fraction >= F   (default 0.4)

local min_requests = 20
local ratio_404 = 0.4
local files = {}

local i = 1
while i <= #arg do
  local a = arg[i]
  if a == "--min-requests" then i = i + 1; min_requests = tonumber(arg[i]) or min_requests
  elseif a == "--404-ratio" then i = i + 1; ratio_404 = tonumber(arg[i]) or ratio_404
  elseif a == "-h" or a == "--help" then
    io.stderr:write("usage: nginxwatch [--min-requests N] [--404-ratio F] FILE|-\n"); os.exit(0)
  else files[#files + 1] = a end
  i = i + 1
end

local SENSITIVE = { "%.env", "wp%-login", "/admin", "%.git", "/phpmyadmin", "/%.aws", "/actuator", "/config%." }

local stats = {}  -- ip -> {total, c404, sensitive}
local function order_ips()
  local t = {}
  for ip in pairs(stats) do t[#t+1] = ip end
  table.sort(t, function(a, b) return stats[a].total > stats[b].total end)
  return t
end

-- combined log: IP - - [time] "METHOD path proto" status size "ref" "ua"
local LINE = '^(%S+) %S+ %S+ %[.-%] "(%S+) (%S-) [^"]*" (%d+)'

local function feed(fh)
  for line in fh:lines() do
    local ip, _method, path, status = line:match(LINE)
    if ip and status then
      local s = stats[ip]
      if not s then s = { total = 0, c404 = 0, sensitive = 0 }; stats[ip] = s end
      s.total = s.total + 1
      if status == "404" then s.c404 = s.c404 + 1 end
      if path then
        for _, pat in ipairs(SENSITIVE) do
          if path:lower():find(pat) then s.sensitive = s.sensitive + 1; break end
        end
      end
    end
  end
end

if #files == 0 then
  feed(io.stdin)
else
  for _, f in ipairs(files) do
    if f == "-" then feed(io.stdin)
    else
      local fh, err = io.open(f, "r")
      if not fh then io.stderr:write("nginxwatch: cannot open " .. f .. ": " .. tostring(err) .. "\n"); os.exit(1) end
      feed(fh); fh:close()
    end
  end
end

-- minimal JSON string escaping
local function jstr(s) return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"') .. '"' end

local findings = {}
local total_lines = 0
for _, ip in ipairs(order_ips()) do
  local s = stats[ip]
  total_lines = total_lines + s.total
  if s.total >= min_requests then
    local r = s.c404 / s.total
    if r >= ratio_404 then
      findings[#findings+1] = string.format('{"type":"scanning","ip":%s,"requests":%d,"not_found":%d,"ratio_404":%.3f}', jstr(ip), s.total, s.c404, r)
    end
    if s.total >= min_requests * 5 then
      findings[#findings+1] = string.format('{"type":"flooding","ip":%s,"requests":%d}', jstr(ip), s.total)
    end
  end
  if s.sensitive > 0 then
    findings[#findings+1] = string.format('{"type":"probing","ip":%s,"sensitive_hits":%d}', jstr(ip), s.sensitive)
  end
end

local nips = 0
for _ in pairs(stats) do nips = nips + 1 end
io.write(string.format('{"tool":"nginxwatch","lines":%d,"sources":%d,"findings":[%s]}\n',
  total_lines, nips, table.concat(findings, ",")))
os.exit(#findings > 0 and 2 or 0)
