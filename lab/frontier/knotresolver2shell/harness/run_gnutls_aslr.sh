#!/bin/bash
# Three independent ASLR-on oracle samples from the pinned 6.4.0 build.
# Measures buf/slot1 low-16-bit stability and libc/system variation.
# Loopback only; no host sysctl changes.
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
for i in 1 2 3; do
  EVID="$BASE/harness/aslr-on-$i.gdb.log"
  : > "$EVID"
  pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
  sleep 1
  gdb -q -batch -x "$BASE/harness/gnutls-owner-aslr.gdb" "$KRESD" > "$EVID" 2>&1 &
  GB=$!
  sleep 7
  "$BASE/poc/venv/bin/python" "$BASE/harness/ksl_stalled.py" 8855 1 > "$BASE/harness/aslr-on-$i.driver.log" 2>&1
  sleep 4
  kill -9 $GB 2>/dev/null
  pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
  echo "=== sample $i ==="
  grep -E 'ASLR_ON_(PRE_F6|SYSTEM|NO_HIT)' "$EVID"
  sleep 1
done
