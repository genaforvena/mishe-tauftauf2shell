#!/usr/bin/env bash
# Adjacent Ruby 3.4.12 -> 3.4.13 String#setbyte stale-length lane.
# Runs the coercion/shrink matrix on vulnerable and fixed plain + ASan builds,
# then reads the chosen byte at the chosen stale offset with gdb (read only).
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/setbyte-stale
mkdir -p "$EVID"
: >"$EVID/matrix.txt"

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  case "$build" in
    *-plain) ruby="lab/build/plain/${build%-plain}/ruby" ;;
    *) ruby="lab/build/$build/bin/ruby" ;;
  esac
  for spec in 'slice 700 88' 'nochange 700 88' 'replace 700 88' 'slice 12 88' 'slice 700 0' 'slice 700 255'; do
    set -- $spec
    out="$EVID/$build-$1-$2-$3"
    ASAN_OPTIONS=detect_leaks=0 timeout 30 "$ruby" lab/repro/ruby2shell-setbyte-stale.rb "$@" >"$out.out" 2>"$out.err"
    rc=$?
    asan=$(grep -c 'ERROR: AddressSanitizer' "$out.err" || true)
    line=$(printf '%s %s %s rc=%d asan=%s %s' "$build" "$1-$2-$3" "" "$rc" "$asan" "$(cat "$out.out")")
    echo "$line"
    echo "$line" >>"$EVID/matrix.txt"
  done
done

# gdb reads the byte at ptr before and after the store on the vulnerable build.
# No register, pointer or memory is written by the debugger.
: >"$EVID/gdb-sweep.txt"
for off in 100 700; do
  for val in 0 88 255; do
    log="$EVID/gdb-$off-$val.log"
    gdb -q -batch -x lab/repro/ruby2shell-setbyte-stale-gdb.cmd \
      --args lab/build/ruby-3.4.12/ruby lab/repro/ruby2shell-setbyte-stale.rb slice "$off" "$val" \
      >"$log" 2>&1
    before=$(grep -E '^0x[0-9a-f]+:[[:space:]]+0x' "$log" | head -1)
    after=$(grep -E '^0x[0-9a-f]+:[[:space:]]+0x' "$log" | tail -1)
    line="gdb off=$off val=$val before=$before after=$after"
    echo "$line"
    echo "$line" >>"$EVID/gdb-sweep.txt"
  done
done

# Fixed 3.4.13: revalidation rejects index 700 before the store, so the
# breakpoint on the fixed store line is never reached.
gdb -q -batch -x lab/repro/ruby2shell-setbyte-stale-fixed-gdb.cmd \
  --args lab/build/ruby-3.4.13/ruby lab/repro/ruby2shell-setbyte-stale.rb slice 700 88 \
  >"$EVID/gdb-fixed-control.log" 2>&1
echo "gdb fixed control breakpoint hits: $(grep -c 'hit Breakpoint' "$EVID/gdb-fixed-control.log")"
