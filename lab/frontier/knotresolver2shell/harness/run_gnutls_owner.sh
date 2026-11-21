#!/bin/bash
# Loopback-only: dump the buf+6144 neighbour before F6 overwrites it.
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
EVID="$BASE/harness/gnutls-owner.txt"
: > "$EVID"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
pkill -9 -f 'gnutls-owner.gdb' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/gnutls-owner.gdb" "$KRESD" > "$EVID" 2>&1 &
GB=$!
echo "[runner] gdb pid=$GB"
sleep 5
ss -lun | grep 8855 || echo "no 8855 socket yet"
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_marker.py" 8855 2>&1
sleep 3
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
cat "$EVID"
echo "=== END ==="
