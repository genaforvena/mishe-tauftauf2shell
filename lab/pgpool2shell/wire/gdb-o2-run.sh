#!/bin/bash
# W2: capture the -O2 adjacent slot at the real parser fault. Starts a
# loopback synthetic peer with a 2 s delay (so gdb installs the parser
# breakpoint before the trigger arrives), then gdb-follows the plant-built
# 4.7.2 -O2 daemon into its watchdog child. No non-loopback traffic.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VULN="${TMPDIR:-/tmp}/w2-pgpool-o2/pgpool-II-4.7.2/src/pgpool"
OUT="$HERE/o2-gdb"

if ss -ltn 2>/dev/null | grep -qE ':(19003|19004|19005)\b'; then
    echo "watchdog ports busy (possibly witness replay); retry later" >&2
    exit 3
fi
if [ ! -x "$VULN" ]; then
    echo "build first: bash lab/pgpool2shell/wire/build-o2.sh" >&2
    exit 2
fi
printf '0\n' > "$HERE/pgpool_node_id"
mkdir -p "$OUT"
python3 "$HERE/peer_delayed.py" 2.0 >"$OUT/peer.txt" 2>&1 &
peer=$!
sleep 0.3
cd "$ROOT" || exit 1
gdb -q -batch -x "$HERE/gdb-o2.cmd" "$VULN" >"$OUT/trace.txt" 2>&1
rc=$?
kill "$peer" 2>/dev/null || true
wait "$peer" 2>/dev/null || true
echo "gdb rc=$rc"
grep -a -E 'HIT wd_json_data|^\$[0-9]+ =|SIGSEGV' "$OUT/trace.txt" | head -40
