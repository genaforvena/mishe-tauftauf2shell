#!/bin/bash
# Wake-19 bounded ASLR-on inventory: one sample per invocation, distinct logs.
# Reuses the committed gdb script; records `info proc mappings` in the same log
# so every sampled pointer can be resolved to a library file offset.
# Loopback only; host sysctl untouched.
set +e
SUF="${1:-1}"
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
EVID="$BASE/harness/aslr-inventory-w19-$SUF.gdb.log"
DRV="$BASE/harness/aslr-inventory-w19-$SUF.driver.log"
: > "$EVID"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/aslr-pointer-inventory.gdb" "$KRESD" > "$EVID" 2>&1 &
GB=$!
sleep 7
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_stalled.py" 8855 1 > "$DRV" 2>&1
sleep 4
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
grep -E 'INV_PRE_F6|INV_SYSTEM|INV_NO_HIT' "$EVID"
