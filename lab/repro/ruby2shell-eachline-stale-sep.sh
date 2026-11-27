#!/usr/bin/env bash
# W331: vulnerable 3.4.12 vs fixed 3.4.13 differential for the stale
# `String#each_line` separator buffer.  Plain + ASan; local script execution
# only, no network, no debugger writes.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/eachline-stale-sep
mkdir -p "$EVID"
: >"$EVID/matrix.txt"
for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  case "$build" in
    *-plain) rb="lab/build/plain/${build%-plain}/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for action in none grow shrink; do
    for pair in 64:8192 4096:16384; do
      sep=${pair%:*}; grow=${pair#*:}
      tag="$build-$action-$sep"
      W331L_ACTION="$action" W331L_SEP="$sep" W331L_GROW="$grow" \
        ASAN_OPTIONS=detect_leaks=0 timeout 30 "$rb" \
        lab/repro/ruby2shell-eachline-stale-sep.rb \
        >"$EVID/$tag.out" 2>"$EVID/$tag.err"
      rc=$?
      asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
      kind=$(grep -m1 -E 'ERROR: AddressSanitizer: [a-z-]+' "$EVID/$tag.err" || true)
      frame=$(grep -m1 -E 'rb_memsearch|rb_str_enumerate_lines|memcmp' "$EVID/$tag.err" || true)
      result=$(grep '^RESULT ' "$EVID/$tag.out" | tail -1)
      echo "$build action=$action sep=$sep grow=$grow rc=$rc asan=$asan ${kind} ${frame} ${result:-NO_RESULT}" \
        | sed 's/  */ /g' >>"$EVID/matrix.txt"
    done
  done
done
cat "$EVID/matrix.txt"
