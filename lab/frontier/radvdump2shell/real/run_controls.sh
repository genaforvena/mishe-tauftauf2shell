#!/bin/bash
# Lab-only controls for the radvdump rung-5 wire claim.
# Every RA goes to ::1%lo only. No external address is contacted.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
MARKER=/tmp/radvdump2shell-marker
cd "$HERE"

run_case() {
  local name="$1" bin="$2" mode="$3" out="$4" secs="$5"
  sudo -n rm -f "$MARKER" "$out"
  (
    sleep 2
    sudo -n python3 "$HERE/send_marker.py" "$mode"
  ) &
  local sleeper=$!
  sudo -n "$HERE/$bin" -d 4 > "$out" 2>&1 &
  local target=$!
  sleep "$secs"
  kill "$target" 2>/dev/null || true
  wait "$target" 2>/dev/null || true
  kill "$sleeper" 2>/dev/null || true
  wait "$sleeper" 2>/dev/null || true
  if [ -f "$MARKER" ]; then
    echo "$name: MARKER_PRESENT (unexpected)"
  else
    echo "$name: MARKER_ABSENT"
  fi
}

# 1. RFC-conformant length byte on the vulnerable binary: no overflow.
run_case safe-input radvd-2.20-plain/radvdump marker-safe \
  evidence/control-safe-input.out 5
# 2. Fixed upstream 2.21 with the same attack RA: option rejected.
run_case fixed-2.21 radvd-2.21/radvdump marker \
  evidence/control-fixed-2.21.out 5
# 3. Vulnerable binary, attack RA, but ASLR left on (no gdb): ROP addresses wrong.
run_case aslr-on radvd-2.20-plain/radvdump marker \
  evidence/control-aslr-on.out 5
# 4. Fortified -O2 build of the pinned vulnerable source: __memcpy_chk aborts.
run_case fortified-o2 radvd-2.20-O2/radvdump marker \
  evidence/control-fortified-o2.out 5
