# nginxwatch — pure Lua, no build step.
LUA    ?= lua
PREFIX ?= /usr/local

.PHONY: all test demo lint install uninstall clean help

all: test

help:
	@echo "targets: test | demo | lint | install | uninstall | clean"

test:
	$(LUA) tests/run.lua

demo:
	LUA="$(LUA)" sh demos/run_all.sh

# luacheck is optional; skips cleanly if not installed.
lint:
	@if command -v luacheck >/dev/null 2>&1; then \
		luacheck nginxwatch.lua tests/run.lua --no-color; \
	else \
		echo "luacheck not installed; skipping (luarocks install luacheck)"; \
	fi

install:
	PREFIX="$(PREFIX)" sh install.sh

uninstall:
	rm -f "$(PREFIX)/bin/nginxwatch"
	rm -rf "$(PREFIX)/lib/nginxwatch"

clean:
	rm -f tests/fixtures/_tail_tmp.log
