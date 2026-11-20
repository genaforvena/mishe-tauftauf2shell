#!/usr/bin/env bash
# Show that each masked empty frame advances the OOB write cursor by exactly
# 4 bytes: the ASan "N bytes after the 1-byte region" offset must grow 4/frame.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export LD_LIBRARY_PATH="$ROOT/deps/cjson/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:print_stacktrace=1"
CFG="$ROOT/run/placement.conf"
printf 'listener 27082 127.0.0.1\nprotocol websockets\nallow_anonymous false\nlog_dest stdout\n' > "$CFG"

for n in 0 1 2 4 8; do
  log="$ROOT/logs/placement-empty$n.log"
  : > "$log"
  "$ROOT/build-2.1.2-asan/src/mosquitto" -c "$CFG" -v >> "$log" 2>&1 &
  pid=$!
  sleep 1.5
  python3 "$ROOT/trigger.py" --port 27082 --empty "$n" --write-len 8 --fill 41 >> "$log" 2>&1
  sleep 0.7
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  echo "=== empty=$n ==="
  grep -E 'WRITE of size|bytes after 1-byte region|ABORTING' "$log" | head -4 || echo "(no ASan report)"
done
