#!/bin/bash
# Live-gdb replay of the CVE-2026-92869 wire trigger against a real pinned
# 4.7.2 watchdog child. Loopback only; kills only this script's own children.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BIN="${TMPDIR:-/tmp}/w108-pgpool-replay/pgpool-II-4.7.2/src/pgpool"
CHOSEN="${1:-0x42424242}"
OUT="${2:-gdb-w7.out}"
PEEROUT="${3:-gdb-w7.peer}"
CMD="${4:-gdb-w7.cmd}"
printf '0\n' > "$HERE/pgpool_node_id"
rm -f /tmp/w7-pgpool.log /tmp/w7-pgpool.pid "$HERE/$OUT" "$HERE/$PEEROUT"
python3 - <<'PY' || exit 2
import socket
for port in (19003, 19004, 19005, 19006):
    s = socket.socket(); s.settimeout(0.3)
    busy = s.connect_ex(("127.0.0.1", port)) == 0
    s.close()
    if busy:
        print(f"port {port} busy; refusing to start", flush=True)
        raise SystemExit(1)
PY
python3 "$HERE/peer.py" 129 "$CHOSEN" 12 >"$HERE/$PEEROUT" 2>&1 &
peer=$!
sleep 0.3
cd "$ROOT" || exit 2
gdb -q -batch -x "$HERE/$CMD" "$BIN" >"$HERE/$OUT" 2>&1
if [ -f /tmp/w7-pgpool.pid ]; then
    main_pid=$(cat /tmp/w7-pgpool.pid)
    kill "$main_pid" 2>/dev/null || true
    sleep 1
    kill -9 "$main_pid" 2>/dev/null || true
fi
kill "$peer" 2>/dev/null || true
wait 2>/dev/null || true
grep -E 'HIT config parser|num_backends|backend_port|0x[0-9a-f]+|wd_json_data.c:|SIGSEGV|segfault|#0 |#1 |#2 ' "$HERE/$OUT" | head -60
