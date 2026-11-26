#!/bin/sh
# One fresh ASan process per shape, on both builds. Records match verdict,
# sanitizer frame and GDB reachability of OP_EXACTN_IC (regexec.c:2830).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/casefold-rawprefix"
mkdir -p "$OUT"
RB="$ROOT/lab/repro/ruby2shell-casefold-rawprefix.rb"
GDB="$ROOT/lab/repro/ruby2shell-casefold-rawprefix.gdb"
NAMES="p0100 p017f p01c0 p0200 p0380 p0580 p1c80 p212a pa78d pfb00"
: > "$OUT/summary.txt"
for v in 3.4.12 3.4.13; do
  for name in $NAMES; do
    log="$OUT/$v-$name.log"
    ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=0 \
      "$ROOT/lab/build/ruby-$v-asan/bin/ruby" "$RB" "$name" > "$log" 2>&1 || true
    match=$(grep -o 'match=[a-z]*' "$log" | head -1 || true)
    asan=$(grep -c 'ERROR: AddressSanitizer' "$log" || true)
    frame=$(grep -o 'in [a-z_]* /home[^ ]*regexec.c:[0-9]*' "$log" | head -1 || true)
    printf 'v=%s case=%s %s asan=%s frame=%s\n' "$v" "$name" "$match" "$asan" "$frame" >> "$OUT/summary.txt"
  done
done
if command -v gdb >/dev/null 2>&1; then
  for name in $NAMES; do
    log="$OUT/gdb-3.4.12-$name.log"
    ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=0 \
      gdb -q -batch -x "$GDB" --args \
      "$ROOT/lab/build/ruby-3.4.12-asan/bin/ruby" "$RB" "$name" > "$log" 2>&1 || true
    hits=$(grep -c 'FOLD_HIT' "$log" || true)
    over=$(grep -c 'OVERRUN' "$log" || true)
    printf 'gdb case=%s fold_hits=%s overrun_hits=%s\n' "$name" "$hits" "$over" >> "$OUT/summary.txt"
  done
fi
cat "$OUT/summary.txt"
