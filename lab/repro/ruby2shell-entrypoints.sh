#!/bin/bash
# Local-only entry-point sweep for CVE-2026-132825. Runs each Veria-named
# entry point on the pinned vulnerable and fixed builds under mtrace, and
# records the adjacent mapping-buffer size LSB (the overflow byte).
# Usage: bash lab/repro/ruby2shell-entrypoints.sh [tag]
set -u
cd "$(dirname "$0")/../.." || exit 1
TAG="${1:-entrypoints-1}"
EV=lab/build/evidence
VULN=lab/build/plain/ruby-3.4.12-plain/bin/ruby
FIXED=lab/build/plain/ruby-3.4.13-plain/bin/ruby
PROBE=lab/repro/ruby2shell-entrypoints.rb
SUMMARY="$EV/$TAG-summary.txt"
mkdir -p "$EV"
printf 'Entry-point sweep (%s, UTC %s)\n' "$TAG" "$(date -u +%FT%TZ)" > "$SUMMARY"
printf 'build=%s fixed=%s tracer=mtrace.so\n' "$( "$VULN" -v )" "$( "$FIXED" -v )" >> "$SUMMARY"

for op in upcase swapcase fold casecmp symcasecmp; do
  for arm in vuln fixed safe; do
    case "$arm" in
      vuln)  bin="$VULN";  n=780 ;;
      fixed) bin="$FIXED"; n=780 ;;
      safe)  bin="$VULN";  n=20 ;;
    esac
    out="$EV/$TAG-$op-$arm.out"
    err="$EV/$TAG-$op-$arm.err"
    env ENC=ISO-8859-1 OP="$op" N="$n" MTRACE_FD=2 \
      LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
      "$bin" "$PROBE" > "$out" 2> "$err"
    rc=$?
    sizefield=$(grep '^F ' "$err" | tail -1 | awk '{print $4}')
    aborts=$(grep -Ec 'corrupted size vs|munmap_chunk|free\(\): invalid pointer' "$err" || true)
    printf '%-12s %-5s n=%-4s rc=%-3s last-sizefield=%-8s aborts=%s  %s\n' \
      "$op" "$arm" "$n" "$rc" "${sizefield:-none}" "$aborts" \
      "$(grep '^entrypoint ' "$out" | tail -1)" >> "$SUMMARY"
  done
done
cat "$SUMMARY"
