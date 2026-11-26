#!/bin/sh
# Fresh ASan process per compile-time shape; both builds; no wire/app/marker.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/compilefold-guards"
mkdir -p "$OUT"
RB="$ROOT/lab/repro/ruby2shell-compilefold-guards.rb"
NAMES="cp-too-big-x cp-too-big-u cp-surrogate cp-max-valid cp-above-bmp-fold hex-cont hex-overlong hex-out-of-range hex-latin1-fold hex-latin1-sharp fold-sharp-latin1 fold-sharp-utf8 fold-cap-sharp fold-ligature raw-u16-unpaired-hi raw-u16-unpaired-lo raw-u32-unpaired-hi raw-u16-valid-pair fold-iota fold-alt-latin1 fold-alt-utf8 group-name-bad group-name-call nest-2000 nest-4000 nest-quant-2000 fold-invalid-latin1"
: > "$OUT/summary.txt"
for v in 3.4.12 3.4.13; do
  for name in $NAMES; do
    log="$OUT/$v-$name.log"
    "$ROOT/lab/build/ruby-$v-asan/bin/ruby" "$RB" "$name" > "$log" 2>&1 || true
    status=$(grep -o -E 'case=[^ ]+ ruby=[^ ]+ enc=[^ ]+ (compiled=[0-9]+|error=[A-Za-z]+)' "$log" | head -1 || true)
    asan=$(grep -c 'ERROR: AddressSanitizer' "$log" || true)
    frame=$(grep -o 'in [a-z_]* /home[^ ]*\(regparse\|regcomp\|regenc\)\.c:[0-9]*' "$log" | head -1 || true)
    printf 'v=%s %s asan=%s frame=%s\n' "$v" "$status" "$asan" "$frame" >> "$OUT/summary.txt"
  done
done
cat "$OUT/summary.txt"
