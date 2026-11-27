#!/usr/bin/env bash
# Adjacent Ruby 3.4.12 String backref-offset lane (same fix series as
# CVE-2026-132825). Runs every arm on vulnerable/fixed plain and ASan builds.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/backref-stale
mkdir -p "$EVID"
for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  case "$build" in
    *-plain) ruby="lab/build/plain/$build/bin/ruby" ;;
    *) ruby="lab/build/$build/bin/ruby" ;;
  esac
  for mode in write-attack write-safe read-attack read-safe chomp; do
    out="$EVID/$build-$mode"
    ASAN_OPTIONS=detect_leaks=0 "$ruby" lab/repro/ruby2shell-backref-stale.rb "$mode" >"$out.out" 2>"$out.err"
    rc=$?
    asan=$(grep -c 'ERROR: AddressSanitizer' "$out.err" || true)
    printf '%s %s rc=%d asan=%s %s\n' "$build" "$mode" "$rc" "$asan" "$(cat "$out.out")"
  done
done
