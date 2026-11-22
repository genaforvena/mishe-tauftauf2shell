#!/bin/bash
# One ASLR-on pointer-inventory sample on the pinned 6.4.0 build.
# Loopback only; no host sysctl changes.
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
EVID="$BASE/harness/aslr-inventory.gdb.log"
: > "$EVID"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/aslr-pointer-inventory.gdb" "$KRESD" > "$EVID" 2>&1 &
GB=$!
sleep 7
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_stalled.py" 8855 1 > "$BASE/harness/aslr-inventory.driver.log" 2>&1
sleep 4
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
grep -E 'INV_PRE_F6|INV_SYSTEM|INV_NO_HIT' "$EVID"
