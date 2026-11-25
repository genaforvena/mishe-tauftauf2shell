#!/bin/bash
# Run the jemalloc exact-size-class overflow with the allocator-native tracer.
# Loopback-free, in-process; analysis only, never an oracle-free claim.
set -u
cd "$(dirname "$0")/../.." || exit 1
TAG="${1:-jemexact1}"
EV=lab/build/evidence
mkdir -p "$EV"
LOG="$EV/jemexact1-$TAG.log"
RB="${JEM_RUBY:-lab/build/plain/ruby-3.4.12-plain/bin/ruby}"
ROOT="$PWD"
LD_PRELOAD="$ROOT/lab/preload/jemtrace.so:libjemalloc.so.2" \
JEMTRACE_FD=2 \
JEMTRACE_WATCH_SIZE="${JEM_WATCH_SIZE:-80}" \
JEMTRACE_ARM_SIZE="${JEM_ARM_SIZE:-79225}" \
JEMTRACE_POST_SIZE="${JEM_POST_SIZE:-79227}" \
JEM_M="${JEM_M:-15}" \
  "$RB" lab/repro/ruby2shell-jemalloc-exact.rb > "$LOG" 2>&1
echo "log=$LOG"
awk '/===REAL===/{p=1} p && /^W /{print}' "$LOG"
grep '^N=' "$LOG"
