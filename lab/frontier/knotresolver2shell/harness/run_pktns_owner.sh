#!/bin/bash
# Loopback-only: start 6.4.0 jemalloc kresd under gdb, fire the F6 OOB body,
# log the in_pktns/hs_pktns/embedded-pktns ownership of buf+6144.
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
EVID="$BASE/harness/pktns-owner.txt"
: > "$EVID"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
pkill -9 -f 'pktns-owner.gdb' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/pktns-owner.gdb" "$KRESD" \
  > "$BASE/harness/pktns-owner-stdout.log" 2>&1 &
GB=$!
echo "[runner] gdb pid=$GB"
sleep 5
ss -lun | grep 8855 || echo "no 8855 socket yet"
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_marker.py" 8855 2>&1
sleep 3
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
echo "=== pktns-owner oracle ==="
cat "$EVID"
echo "=== gdb stdout tail ==="
tail -20 "$BASE/harness/pktns-owner-stdout.log"
echo "=== END ==="
