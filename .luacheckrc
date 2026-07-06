-- luacheck configuration for nginxwatch
std = "lua54"
max_line_length = 120
-- `arg` (script args) and standard globals are read-only for us.
read_globals = { "arg" }
files["tests/run.lua"] = {
  -- test harness intentionally uses long assertion lines
  max_line_length = 160,
}
