#!/usr/bin/env bash
# W348: 14 encodings x 3 stock case-map calls x 3 lengths x 4 builds.
# Evidence is gitignored under lab/build/evidence/enc-case-sweep/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/enc-case-sweep
mkdir -p "$EVID"
: >"$EVID/matrix.txt"
ENCS="ISO-8859-1 ISO-8859-2 ISO-8859-3 ISO-8859-4 ISO-8859-9 ISO-8859-10 ISO-8859-13 ISO-8859-14 ISO-8859-15 ISO-8859-16 Windows-1250 Windows-1252 Windows-1254 Windows-1257"
OPS="upcase fold swapcase"
NS="21 42 83"

run() { # build tag enc op n
  local build="$1" tag="$2" enc="$3" op="$4" n="$5"
  local rb
  case "$build" in
    *-plain) rb="lab/build/plain/$build/bin/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ASAN_OPTIONS=detect_leaks=0 timeout 60 "$rb" \
    lab/repro/ruby2shell-enc-case-sweep.rb "$enc" "$op" "$n" \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  local rc=$?
  local asan kind result
  asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
  kind=$(grep -m1 -E 'SUMMARY: AddressSanitizer: [a-z-]+.*' "$EVID/$tag.err" || true)
  result=$(grep '^ENC ' "$EVID/$tag.out" || true)
  printf '%s enc=%s op=%s n=%s rc=%s asan=%s %s %s\n' \
    "$build" "$enc" "$op" "$n" "$rc" "$asan" "$kind" "${result//$'\n'/ | }" \
    | sed 's/  */ /g'
}

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  for enc in $ENCS; do
    for op in $OPS; do
      for n in $NS; do
        run "$build" "$build-$enc-$op-$n" "$enc" "$op" "$n"
      done
    done
  done
done >"$EVID/matrix.txt"
cat "$EVID/matrix.txt"
