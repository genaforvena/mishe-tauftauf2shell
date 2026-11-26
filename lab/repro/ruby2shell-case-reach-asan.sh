#!/usr/bin/env bash
# Vulnerable/fixed ASan control for the case-reach wire survey.
# ASCII-8BIT Content-Type/Host receivers must not expand 0xDF; ISO-8859-1
# `_method` is the known vulnerable shape. Lab only, no network.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/case-reach
mkdir -p "$EVID"
SCRIPT=lab/repro/ruby2shell-case-reach-asan.rb
CASES=(
  "ascii-up1 upcase ASCII-8BIT 1 plain"
  "ascii-up21 upcase ASCII-8BIT 21 plain"
  "ascii-down21 downcase ASCII-8BIT 21 plain"
  "ascii-downbang21 downcase! ASCII-8BIT 21 plain"
  "ctype-downbang downcase! ASCII-8BIT 0 ctype"
  "host-down downcase ASCII-8BIT 0 host"
  "iso-up21 upcase ISO-8859-1 21 plain"
  "utf8-up21 upcase UTF-8 21 plain"
)
for ver in 12 13; do
  bin="lab/build/ruby-3.4.$ver-asan/bin/ruby"
  for c in "${CASES[@]}"; do
    read -r name mode enc n shape <<<"$c"
    out="$EVID/asan-3.4.$ver-$name.out"
    UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 timeout 60 \
      "$bin" "$SCRIPT" "$mode" "$enc" "$n" "$shape" > "$out" 2>&1
    rc=$?
    summary=$(grep -m1 -E '^mode=|SUMMARY: AddressSanitizer' "$out" || echo '(none)')
    echo "3.4.$ver $name rc=$rc $summary"
  done
done
