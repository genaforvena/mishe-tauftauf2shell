#!/usr/bin/env bash
# W330: vulnerable 3.4.12 vs fixed 3.4.13 differential for the chilled
# `String#append_as_bytes` stale-argument-length OOB store.  Plain + ASan;
# local script execution only, no network or debugger writes.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/chilled-append-bytes-oob
mkdir -p "$EVID"
: >"$EVID/matrix.txt"
sizes=(64:128 4096:8192)
for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  case "$build" in
    *-plain) rb="lab/build/plain/${build%-plain}/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for pair in "${sizes[@]}"; do
    len=${pair%:*}; arg=${pair#*:}
    for action in none recv arg both safe; do
      recv=chilled
      [ "$action" = safe ] && recv=dup
      tag="$build-$len-$action"
      W330B_ACTION="$action" W330B_RECV="$recv" W330B_LEN="$len" \
        W330B_ARG="$arg" W330B_BYTE=90 W330B_N=4096 \
        ASAN_OPTIONS=detect_leaks=0 timeout 30 "$rb" \
        lab/repro/ruby2shell-chilled-append-bytes-oob.rb >"$EVID/$tag.out" 2>"$EVID/$tag.err"
      rc=$?
      asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
      write=$(grep -m1 'WRITE of size' "$EVID/$tag.err" || true)
      frames=$(grep -m1 'rb_str_append_as_bytes .*string.c:' "$EVID/$tag.err" || true)
      result=$(grep '^RESULT ' "$EVID/$tag.out" | tail -1)
      line="$build len=$len arg=$arg action=$action rc=$rc asan=$asan ${write} ${frames} ${result:-NO_RESULT}"
      echo "$line" | sed 's/  */ /g' >>"$EVID/matrix.txt"
    done
  done
done
cat "$EVID/matrix.txt"
