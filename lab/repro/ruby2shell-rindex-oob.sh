#!/usr/bin/env bash
# Adjacent Ruby 3.4.12 String#rindex lane (same fix series as CVE-2026-132825).
# Stock String#rindex only: no monkey patch, debugger, tracer or wire request.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/rindex-oob
mkdir -p "$EVID"
for build in ruby-3.4.12-asan ruby-3.4.13-asan; do
  for mode in pos zero safe; do
    out="$EVID/$build-$mode"
    ASAN_OPTIONS=detect_leaks=0 "lab/build/$build/bin/ruby" \
      lab/repro/ruby2shell-rindex-oob.rb "$mode" >"$out.out" 2>"$out.err"
    rc=$?
    asan=$(grep -c 'ERROR: AddressSanitizer' "$out.err" || true)
    printf '%s %s rc=%d asan=%s %s\n' "$build" "$mode" "$rc" "$asan" "$(cat "$out.out")"
  done
done
