#!/bin/bash
# One-command replay of the radvdump2shell rung-5 wire claim and its controls.
# Lab only: every crafted RA is sent to ::1 scoped to lo. Nothing external.
# Expected: ATTACK => MARKER_PRESENT; all four CONTROLS => MARKER_ABSENT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
echo "=== ATTACK: real 2.20, -O0 non-fortified, gdb ASLR-off, crafted RA -> ::1%lo ==="
timeout 40 ./run_marker.sh marker evidence/replay-attack.out
echo "=== CONTROLS ==="
timeout 55 ./run_controls.sh
echo "=== raw outputs: real/evidence/replay-attack.out and real/evidence/control-*.out ==="
