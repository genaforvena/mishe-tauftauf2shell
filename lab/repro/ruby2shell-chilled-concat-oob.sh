#!/usr/bin/env bash
# W330: 3.4.12 vs 3.4.13 differential for the chilled String#<< codepoint arm.
# Plain + ASan builds; every arm is local script execution, no network.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/chilled-concat-oob
mkdir -p "$EVID"
for enc in US-ASCII UTF-8 EUC-JP; do
  printf '# encoding: %s\n$chilled = "abc"\n' "$enc" >"$EVID/lit-$enc.rb"
done
: >"$EVID/matrix.txt"
codes=(0x41 0xe9 0x100 0x3042 0x10000)
actions=(none enc16 enc32 enc8 encus grow shrink swap to_int)
for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  case "$build" in
    *-plain) rb="lab/build/plain/${build%-plain}/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for enc in US-ASCII UTF-8 EUC-JP; do
    for code in "${codes[@]}"; do
      for action in "${actions[@]}"; do
        tag="$build-$enc-$code-$action"
        W330_ACTION="$action" ASAN_OPTIONS=detect_leaks=0 \
          timeout 30 "$rb" lab/repro/ruby2shell-chilled-concat-oob.rb \
          "$EVID/lit-$enc.rb" "$code" >"$EVID/$tag.out" 2>"$EVID/$tag.err"
        rc=$?
        asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
        result=$(grep '^RESULT ' "$EVID/$tag.out" | tail -1)
        line="$build $enc $code $action rc=$rc asan=$asan ${result:-NO_RESULT}"
        echo "$line" >>"$EVID/matrix.txt"
      done
    done
  done
done
echo "arms: $(wc -l <"$EVID/matrix.txt")"
echo "asan hits: $(grep -c 'asan=[1-9]' "$EVID/matrix.txt" || true)"
