#!/usr/bin/env bash
# Loopback-only VRPN v07.36 wire experiment. Usage: run.sh <outdir>
set -uo pipefail
OUT=${1:?usage: run.sh <outdir>}
mkdir -p "$OUT"
SRV=lab/frontier/vrpn2shell/build-asan-07.36/server_src/vrpn_server
PORT=13893

for case in underflow inrange; do
  if [ "$case" = underflow ]; then IDX=-64; else IDX=4; fi
  ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$SRV" -f lab/frontier/vrpn2shell/vrpn.cfg -quiet "$PORT" >"$OUT/server-$case.stdout" 2>"$OUT/server-$case.stderr" &
  PID=$!
  sleep 0.7
  python3 lab/frontier/vrpn2shell/wire_inject.py --index "$IDX" --port "$PORT" \
    >"$OUT/client-$case.txt" 2>&1
  sleep 0.5
  kill -0 "$PID" 2>/dev/null && echo "server_alive_after_$case" >>"$OUT/client-$case.txt" \
    || echo "server_dead_after_$case" >>"$OUT/client-$case.txt"
  kill "$PID" 2>/dev/null
  wait "$PID" 2>/dev/null
  sleep 0.3
done
