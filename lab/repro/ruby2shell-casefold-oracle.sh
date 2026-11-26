#!/bin/sh
# Reproduce the case-fold one-byte-exact OOB oracle experiment.
# Builds an analysis-only extension for plain Ruby 3.4.12 (vulnerable) and
# 3.4.13 (fixed), primes the small free chunk with each byte 0..255, compiles
# /s/i and records whether the folded-subject match outcome can be steered.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/casefold-oracle"
mkdir -p "$OUT"

for pair in 3.4.12:312 3.4.13:313; do
  v=${pair%%:*}; t=${pair##*:}
  R="$ROOT/lab/build/plain/ruby-$v-plain"
  mkdir -p "$ROOT/lab/build/casefold-oracle-$t"
  gcc -shared -fPIC -O0 -g \
    -I"$ROOT/lab/build/ruby-$v" \
    -I"$R/include/ruby-3.4.0" \
    -I"$R/include/ruby-3.4.0/x86_64-linux" \
    -o "$ROOT/lab/build/casefold-oracle-$t/ruby2shell_casefold_oracle.so" \
    "$ROOT/lab/repro/ruby2shell-casefold-oracle.c"
done

for pair in 3.4.12:312 3.4.13:313; do
  v=${pair%%:*}; t=${pair##*:}
  R="$ROOT/lab/build/plain/ruby-$v-plain/bin/ruby"
  S="$ROOT/lab/build/casefold-oracle-$t/ruby2shell_casefold_oracle.so"
  : > "$OUT/sweep-$v.txt"
  b=0
  while [ "$b" -lt 256 ]; do
    "$R" "$ROOT/lab/repro/ruby2shell-casefold-oracle.rb" "$S" "$b" 1 \
      >> "$OUT/sweep-$v.txt"
    b=$((b + 1))
  done
  echo "== $v rows=$(wc -l < "$OUT/sweep-$v.txt") =="
  echo "distinct outcome sets:"
  sed -E 's/^ruby=[0-9.]+ byte=0x[0-9a-f]+ count=1 //' "$OUT/sweep-$v.txt" \
    | sort | uniq -c
done
