#!/bin/sh
# Analysis-only probe of the unconsumed regexec.c:1893 sibling hunk
# (string_cmp_ic without an s2 >= text_end guard). Each case runs in a fresh
# ASan process so an abort cannot hide later cases. No wire/app/marker.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/casefold-backref-ic"
mkdir -p "$OUT"
RB="$ROOT/lab/repro/ruby2shell-casefold-backref-ic.rb"
NAMES="sss-then-two-long-s ssss-then-three-long-s s-then-long-s ss-then-dotted ss-then-cap-sharp s-then-sharp ascii-control miss-control"

: > "$OUT/summary.txt"
for v in 3.4.12 3.4.13; do
  for name in $NAMES; do
    log="$OUT/$v-$name.log"
    "$ROOT/lab/build/ruby-$v-asan/bin/ruby" "$RB" "$name" > "$log" 2>&1 || true
    match=$(grep -o 'match=[a-z]*' "$log" | head -1 || true)
    asan=$(grep -c 'ERROR: AddressSanitizer' "$log" || true)
    frame=$(grep -o 'in [a-z_]* /home[^ ]*regexec.c:[0-9]*' "$log" | head -1 || true)
    printf 'v=%s case=%s %s asan=%s frame=%s\n' "$v" "$name" "$match" "$asan" "$frame" >> "$OUT/summary.txt"
  done
done
cat "$OUT/summary.txt"
