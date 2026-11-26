#!/bin/sh
# Fresh ASan process per shape; both builds; report match and sanitizer frame.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/casefold-exactn"
mkdir -p "$OUT"
RB="$ROOT/lab/repro/ruby2shell-casefold-exactn.rb"
NAMES="a1-sharp a1-capsharp a1-ffi a1-iota-dia a1-long-s an-ss-sharp an-3-sharp an-iota-dia an-ffi an-foldlit-sharp an-foldlit-greek an-foldlit-ffi an-foldlit-mixed an-dot-foldlit-greek an-dot-s-greek an-2dot-ss-greek noanchor-sharp lookbehind alt a1-tail115 a1-tail116"
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
