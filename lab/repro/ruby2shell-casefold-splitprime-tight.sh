#!/bin/sh
# Canonical driver for the split-unsorted-remainder byte-oracle experiment.
# Analysis-only: no app, wire, marker or debugger writes. Builds the extension
# for plain Ruby 3.4.12 (affected) and 3.4.13 (fixed), fills a freed chunk with
# each fold's second byte, splits it via an unsorted remainder, compiles the
# one-byte-exact regex inside C immediately after the split, and records
# match? plus GDB-read exact+1 on 3.4.12.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/casefold-splitprime-tight"
mkdir -p "$OUT"
C="$ROOT/lab/repro/ruby2shell-casefold-splitprime-tight.c"
RB="$ROOT/lab/repro/ruby2shell-casefold-splitprime-tight.rb"
GDB="$ROOT/lab/repro/ruby2shell-casefold-splitprime-tight.gdb"

for pair in 3.4.12:312 3.4.13:313; do
  v=${pair%%:*}; t=${pair##*:}
  R="$ROOT/lab/build/plain/ruby-$v-plain"
  D="$ROOT/lab/build/casefold-splitprime-tight-$t"
  mkdir -p "$D"
  gcc -shared -fPIC -O0 -g \
    -I"$ROOT/lab/build/ruby-$v" \
    -I"$R/include/ruby-3.4.0" \
    -I"$R/include/ruby-3.4.0/x86_64-linux" \
    -o "$D/ruby2shell_casefold_splitprime_tight.so" "$C"
done

BIG=65536
FRONT=61440
: > "$OUT/plain.txt"
for pair in 3.4.12:312 3.4.13:313; do
  v=${pair%%:*}; t=${pair##*:}
  R="$ROOT/lab/build/plain/ruby-$v-plain/bin/ruby"
  S="$ROOT/lab/build/casefold-splitprime-tight-$t/ruby2shell_casefold_splitprime_tight.so"
  for tune in default no-tcache no-fastbin; do
    case "$tune" in
      default)    "$R" "$RB" "$S" "$BIG" "$FRONT" 1 >> "$OUT/plain.txt" ;;
      no-tcache)  GLIBC_TUNABLES=glibc.malloc.tcache_count=0 \
                    "$R" "$RB" "$S" "$BIG" "$FRONT" 1 >> "$OUT/plain.txt" ;;
      no-fastbin) GLIBC_TUNABLES=glibc.malloc.tcache_count=0:glibc.malloc.mxfast=0 \
                    "$R" "$RB" "$S" "$BIG" "$FRONT" 1 >> "$OUT/plain.txt" ;;
    esac
  done
done

R312="$ROOT/lab/build/plain/ruby-3.4.12-plain/bin/ruby"
S312="$ROOT/lab/build/casefold-splitprime-tight-312/ruby2shell_casefold_splitprime_tight.so"
for tune in default no-tcache no-fastbin; do
  log="$OUT/gdb-$tune.log"
  case "$tune" in
    default)    gdb -q -batch -x "$GDB" --args \
                  "$R312" "$RB" "$S312" "$BIG" "$FRONT" 1 > "$log" 2>&1 || true ;;
    no-tcache)  GLIBC_TUNABLES=glibc.malloc.tcache_count=0 gdb -q -batch -x "$GDB" --args \
                  "$R312" "$RB" "$S312" "$BIG" "$FRONT" 1 > "$log" 2>&1 || true ;;
    no-fastbin) GLIBC_TUNABLES=glibc.malloc.tcache_count=0:glibc.malloc.mxfast=0 \
                  gdb -q -batch -x "$GDB" --args \
                  "$R312" "$RB" "$S312" "$BIG" "$FRONT" 1 > "$log" 2>&1 || true ;;
  esac
  printf '== %s hits=%s ==\n' "$tune" "$(grep -c FOLD_HIT "$log" || true)"
  grep 'FOLD_HIT n=' "$log" | head -8 || true
done

echo '== plain outcomes =='
grep -o 'match=[a-z]*' "$OUT/plain.txt" | sort | uniq -c
echo '== true rows =='
grep 'match=true' "$OUT/plain.txt" || true
