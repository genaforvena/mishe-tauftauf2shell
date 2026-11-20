#!/bin/bash
# Stage C — tcache poisoning driver: 5 attack runs + 3 control runs,
# in-process (same scope as lab/repro/ruby2shell-stageB.rb; the HTTP
# variants are separate sections). See the .rb header for the chain.
#
# Per run: fresh process, trace to lab/build/evidence/stageC-*.trace
# (fd 2: mtrace lines + this script's own STDERR markers), program
# output to stageC-*.out. Each attack run must show:
#   verdict=poisoned                       (in the .out)
#   a "M <seq> 3e9 <target-hex>" line      (in the .trace, target read
#                                          from the .out's target= line)
# Each control run must show verdict=clean and NO-ABORT, and its trace
# must NOT contain the run's target address as a 3e9 pop.
set -u
cd "$(dirname "$0")/../.." || exit 1
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
RBSCRIPT=lab/repro/ruby2shell-stageC.rb
EV=lab/build/evidence
mkdir -p "$EV"

run_one() {  # $1 = tag, $2 = attack|control
  local TAG="$1" MODE="$2"
  local TRACE="$EV/stageC-$TAG.trace" OUT="$EV/stageC-$TAG.out"
  if [ "$MODE" = control ]; then
    STAGEC_CONTROL=1 STAGEC_TRACE="$PWD/$TRACE" MTRACE_FD=2 \
      LD_PRELOAD=$PWD/lab/preload/mtrace.so \
      $RB $RBSCRIPT > "$OUT" 2> "$TRACE"
  else
    STAGEC_TRACE="$PWD/$TRACE" MTRACE_FD=2 \
      LD_PRELOAD=$PWD/lab/preload/mtrace.so \
      $RB $RBSCRIPT > "$OUT" 2> "$TRACE"
  fi
  local RC=$?
  local TARGET
  TARGET=$(sed -n 's/^target=0x//p' "$OUT")
  local VERDICT
  VERDICT=$(sed -n 's/^verdict=//p' "$OUT")
  local POPLINE=0
  [ -n "$TARGET" ] && \
    POPLINE=$(grep -c "^M [0-9]* 3e9 $TARGET " "$TRACE" || true)
  echo "== $TAG rc=$RC verdict=$VERDICT target=0x$TARGET popline=$POPLINE"
  if [ "$MODE" = attack ]; then
    grep -q '^verdict=poisoned$' "$OUT" && [ "$POPLINE" -ge 1 ] && \
      echo "   PASS (poisoned readback + mtrace pop at target)" || \
      echo "   FAIL"
  else
    grep -q '^verdict=clean$' "$OUT" && grep -q '^NO-ABORT$' "$OUT" && \
      [ "$POPLINE" -eq 0 ] && \
      echo "   PASS (control clean, no pop at target)" || echo "   FAIL"
  fi
}

echo "== attack runs"
for i in 1 2 3 4 5; do run_one "$i" attack; done
echo "== control runs"
for i in 1 2 3; do run_one "control-$i" control; done
