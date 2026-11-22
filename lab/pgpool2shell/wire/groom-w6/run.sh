#!/bin/bash
# Replay the W6 cross-command grooming negative. Loopback only; never kills a
# process it does not own. Outputs go beside this script, not into /tmp.
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../../" && pwd)"
BIN="${TMPDIR:-/tmp}/w108-pgpool-replay/pgpool-II-4.7.2/src/pgpool"
cd "$REPO" || exit 1

if [ ! -x "$BIN" ]; then
    echo "build the pinned 4.7.2 tree first: bash lab/frontier/pgpool2shell/harness/run.sh" >&2
    exit 2
fi
if ss -ltn 2>/dev/null | grep -qE ':(19003|19004|19005|19006)\b'; then
    echo "lab watchdog ports busy; refusing to start" >&2
    exit 3
fi
printf '0\n' > "$HERE/../pgpool_node_id"

PEER_OUT="$HERE/replay-peer.out"
GDB_OUT="$HERE/replay-gdb.out"
rm -f "$PEER_OUT" "$GDB_OUT"
python3 "$HERE/peer.py" 14 2 > "$PEER_OUT" 2>&1 &
PEER=$!
timeout 70 gdb -q -batch -x "$HERE/gdb.cmd" "$BIN" > "$GDB_OUT" 2>&1
RC=$?
kill "$PEER" 2>/dev/null
wait "$PEER" 2>/dev/null
pkill -f 'pgpool -n -D -f lab/pgpool2shell/wire/pgpool-vuln.conf' 2>/dev/null
echo "gdb_rc=$RC (full trace: $GDB_OUT)"
