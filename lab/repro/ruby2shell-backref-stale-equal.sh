#!/usr/bin/env bash
# Drive the equal-length stale-backref arms on vulnerable/fixed plain and ASan
# builds, then dump the chosen bytes with a debugger READ on vulnerable plain.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/backref-stale-equal
mkdir -p "$EVID"
for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  case "$build" in
    *-plain) ruby="lab/build/plain/$build/bin/ruby" ;;
    *) ruby="lab/build/$build/bin/ruby" ;;
  esac
  for spec in attack:0 attack:8 attack:64 attack:700 attack:4096 safe:0 safe:700 safe:4096 visible:8 visible:100 visible-safe:8 visible-safe:100; do
    out="$EVID/$build-${spec/:/-}"
    UBSAN_OPTIONS=halt_on_error=0 ASAN_OPTIONS=detect_leaks=0 \
      "$ruby" lab/repro/ruby2shell-backref-stale-equal.rb "$spec" \
      >"$out.out" 2>"$out.err"
    rc=$?
    asan=$(grep -c 'ERROR: AddressSanitizer' "$out.err" || true)
    printf '%s %-12s rc=%d asan=%s %s\n' "$build" "$spec" "$rc" "$asan" "$(cat "$out.out")"
  done
done
gdb -q -batch -x lab/repro/ruby2shell-backref-stale-equal-gdb.cmd \
  --args lab/build/plain/ruby-3.4.12-plain/bin/ruby -e '' \
  >"$EVID/gdb-chosen.out" 2>&1
echo "--- gdb chosen-byte dump (vulnerable plain, debugger READ only) ---"
grep -E 'CHOSEN memmove|AFTER chosen|^0x' "$EVID/gdb-chosen.out" | head -20
