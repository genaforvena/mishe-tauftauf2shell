#!/usr/bin/env bash
# Loopback-only differential: affected 2.1.2 vs fixed 2.1.3.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT/logs" "$ROOT/run"
export LD_LIBRARY_PATH="$ROOT/deps/cjson/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:print_stacktrace=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0"

run_one() {
  local ver="$1" port="$2"
  local bin="$ROOT/build-$ver-asan/src/mosquitto"
  local cfg="$ROOT/run/$ver.conf"
  printf 'listener %s 127.0.0.1\nprotocol websockets\nallow_anonymous false\nlog_dest stdout\nlog_type all\n' \
    "$port" > "$cfg"
  : > "$ROOT/logs/broker-$ver.log"
  "$bin" -c "$cfg" -v > "$ROOT/logs/broker-$ver.log" 2>&1 &
  local pid=$!
  sleep 2
  python3 "$ROOT/trigger.py" --port "$port" > "$ROOT/logs/trigger-$ver.log" 2>&1
  sleep 1
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  echo "========== $ver (port $port) =========="
  cat "$ROOT/logs/trigger-$ver.log"
  echo "--- broker log (last 80) ---"
  tail -80 "$ROOT/logs/broker-$ver.log"
}

run_one 2.1.2 27080
run_one 2.1.3 27081
