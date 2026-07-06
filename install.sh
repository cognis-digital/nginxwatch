#!/usr/bin/env sh
# nginxwatch installer for Linux/macOS.
# Installs a `nginxwatch` launcher into PREFIX/bin (default /usr/local).
# Requires a Lua 5.x interpreter on PATH (lua, lua5.4, lua5.3, or luajit).
set -eu

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# locate a lua interpreter
LUA=""
for cand in lua5.4 lua5.3 lua luajit; do
  if command -v "$cand" >/dev/null 2>&1; then LUA="$cand"; break; fi
done
if [ -z "$LUA" ]; then
  echo "nginxwatch: no Lua interpreter found (install lua5.4: apt/brew)." >&2
  exit 1
fi

LIBDIR="$PREFIX/lib/nginxwatch"
echo "Installing nginxwatch.lua -> $LIBDIR"
mkdir -p "$LIBDIR" "$BINDIR"
cp "$SRC_DIR/nginxwatch.lua" "$LIBDIR/nginxwatch.lua"

LAUNCHER="$BINDIR/nginxwatch"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env sh
exec $LUA "$LIBDIR/nginxwatch.lua" "\$@"
EOF
chmod +x "$LAUNCHER"

echo "Installed: $LAUNCHER (using $LUA)"
echo "Try: nginxwatch --version"
