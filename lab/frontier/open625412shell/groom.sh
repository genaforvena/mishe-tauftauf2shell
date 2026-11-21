#!/bin/bash
# Rung-4 grooming probe: can the stale backpointer write land on a live object?
# Usage: bash run.sh <outdir> && bash groom.sh <outdir>
# Requires the ASan build trees produced by run.sh in <outdir>/1.5.4 and /1.5.6.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(realpath -m "${1:?usage: groom.sh <outdir>}")"
mkdir -p "$OUT/groom"
: > "$OUT/groom/pass.log"
p(){ echo "PASS $1" | tee -a "$OUT/groom/pass.log"; }
f(){ echo "FAIL $1" | tee -a "$OUT/groom/pass.log"; exit 1; }

for v in 1.5.4 1.5.6; do
  T="$OUT/$v"
  [ -f "$T/out-asan/bin/libopen62541.a" ] || f "missing ASan build for $v (run run.sh first)"
  gcc -std=c99 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
    -I"$T/out-asan/src_generated" -I"$T/include" -I"$T/plugins/include" \
    -I"$T/deps" -I"$T/src" -I"$T" -o "$OUT/groom/harness-$v" \
    "$HERE/groom_harness.c" "$T/out-asan/bin/libopen62541.a" -lpthread -lm \
    > "$OUT/groom/build-$v.log" 2>&1 || f "compile failed for $v"
done
p 'groom harness compiled against both pinned ASan builds'

# Quarantine must be disabled for a freed 352-byte chunk to be recycled by the
# very next UA_Subscription allocation. This is a stated lab condition, not a
# default allocator configuration.
GROOM_OPTS='detect_leaks=0:quarantine_size_mb=0'
ASAN_OPTIONS="$GROOM_OPTS" "$OUT/groom/harness-1.5.4" > "$OUT/groom/vuln.log" 2>&1
VRC=$?
ASAN_OPTIONS="$GROOM_OPTS" OA_RUN_SAMPLING=1 "$OUT/groom/harness-1.5.4" \
  > "$OUT/groom/vuln-sampling.log" 2>&1
VSRC=$?
ASAN_OPTIONS="$GROOM_OPTS" OA_SKIP_DELETE=1 OA_RUN_SAMPLING=1 "$OUT/groom/harness-1.5.4" \
  > "$OUT/groom/vuln-control.log" 2>&1
VCRC=$?
ASAN_OPTIONS="$GROOM_OPTS" OA_RUN_SAMPLING=1 "$OUT/groom/harness-1.5.6" \
  > "$OUT/groom/fixed.log" 2>&1
FRC=$?

grep -q 'sizeof(UA_Subscription)=352 offset(samplingMonitoredItems)=200' "$OUT/groom/vuln.log" && \
  p 'stale backpointer offset in UA_Subscription is byte 200 of 352'
grep -q 'same_chunk=1' "$OUT/groom/vuln.log" && \
  p 'freed chunk reclaimed by a live replacement subscription'
grep -q 'aliased_with_old_mon=0' "$OUT/groom/vuln.log" && \
  p 'live replacement monitored item is a distinct object'
grep -q 'replacementHeadAfter=(nil) samplingCountAfter=0 changed=1' "$OUT/groom/vuln.log" && \
  p 'stale write overwrote the live replacement sampling head (1 item -> 0)'
[ "$VRC" -eq 0 ] && p "vulnerable groom run clean rc=$VRC (write landed on allocated memory)"
grep -q 'replacementHeadAfter=0x.* samplingCountAfter=1 changed=0' "$OUT/groom/vuln-control.log" && \
  p 'control without stale delete: live head intact'
[ "$VCRC" -eq 0 ] && p "control rc=$VCRC"
grep -q 'replacementHeadAfter=0x.* samplingCountAfter=1 changed=0' "$OUT/groom/fixed.log" && \
  p 'fixed 1.5.6: live head intact through the same delete'
[ "$FRC" -eq 0 ] && p "fixed rc=$FRC"
printf 'INFO vulnerable-with-sampling rc=%s (downstream assertion is recorded, not claimed as pointer control)\n' "$VSRC"

if grep -q 'replacementHeadAfter=(nil) samplingCountAfter=0 changed=1' "$OUT/groom/vuln.log" && \
   grep -q 'samplingCountAfter=1 changed=0' "$OUT/groom/fixed.log"; then
  p "trace sha256=$(sha256sum "$OUT/groom/pass.log" | cut -d' ' -f1)"
else
  f 'grooming differential not observed'
fi
