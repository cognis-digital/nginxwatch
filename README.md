# nginxwatch

**Lua 5.x** — Access-log scanner — flags scanning (404 floods), sensitive-path probing, request flooding.

[![ci](https://github.com/cognis-digital/nginxwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/nginxwatch/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-Lua-informational)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** — 370+ single-purpose, self-hostable tools. Like every tool in the suite, `nginxwatch` is single-purpose, emits machine-readable JSON, and exits non-zero when it finds something (CI-friendly).


<!-- cognis:example:start -->
## 🔎 Example output

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"nginx_config": {
"server_name": "example.com",
"listen_port": 8080,
"status": "online"
},
"processes": [
{
"pid": 1234,
"cpu_usage": 2.5,
"memory_usage": 128
},
{
"pid": 5678,
"cpu_usage": 1.8,
"memory_usage": 256
}
]
}
```

<!-- cognis:example:end -->

## Build / run

```bash
lua5.4 nginxwatch.lua sample.log   # no build step; pure Lua
```

## Usage

```
lua nginxwatch.lua /var/log/nginx/access.log
cat access.log | lua nginxwatch.lua -
  --min-requests N   only consider IPs with >= N requests (default 20)
  --404-ratio F      flag scanning when 404 fraction >= F (default 0.4)
```

## Output

A JSON object on stdout. Exit code **2** when findings exist, **0** when clean, **1** on error — so you can gate CI/pipelines on it.

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
