#!/bin/sh
# Does the case-fold OOB read produce a stable boolean oracle for any Unicode
# fold whose second byte could match a stale pointer fragment? Enumerate the
# candidate folds once, confirm the OOB read under ASan on 3.4.12, then run 32
# fresh plain processes per candidate on 3.4.12 and fixed 3.4.13. A candidate
# is an oracle only if true is stable on 3.4.12 and false on 3.4.13.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT="$ROOT/lab/build/evidence/casefold-foldbytes"
mkdir -p "$OUT"
SCRIPT="$ROOT/lab/repro/ruby2shell-casefold-foldbytes.rb"
P312="$ROOT/lab/build/plain/ruby-3.4.12-plain/bin/ruby"
P313="$ROOT/lab/build/plain/ruby-3.4.13-plain/bin/ruby"
A312="$ROOT/lab/build/ruby-3.4.12-asan/bin/ruby"
A313="$ROOT/lab/build/ruby-3.4.13-asan/bin/ruby"

"$P312" "$SCRIPT" candidates > "$OUT/candidates.txt"
head -1 "$OUT/candidates.txt"

: > "$OUT/asan.txt"
: > "$OUT/plain-3.4.12.txt"
: > "$OUT/plain-3.4.13.txt"
while read -r cp needle fold; do
  case "$cp" in U+*) ;; *) continue ;; esac
  c=${cp#U+}
  for pair in "312:$A312" "313:$A313"; do
    tag=${pair%%:*}
    bin=${pair#*:}
    f="$OUT/asan-$tag-$c.out"
    UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
      ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 timeout 60 \
      "$bin" "$SCRIPT" trial "$c" "$needle" >"$f" 2>&1 || true
    oob=$(grep -c 'heap-buffer-overflow' "$f" || true)
    site=$(grep -c 'str_lower_case_match' "$f" || true)
    printf '3.4.%s cp=%s fold=%s oob=%s site=%s %s\n' "$tag" "$cp" "$fold" "$oob" "$site" "$f" >> "$OUT/asan.txt"
  done
  for pair in "3.4.12:$P312" "3.4.13:$P313"; do
    v=${pair%%:*}
    bin=${pair#*:}
    dest="$OUT/plain-$v.txt"
    i=0
    while [ "$i" -lt 32 ]; do
      "$bin" "$SCRIPT" trial "$c" "$needle" >> "$dest"
      i=$((i + 1))
    done
  done
  printf '%s fold=%s asan-312=%s\n' "$cp" "$fold" \
    "$(grep "cp=$cp " "$OUT/asan.txt" | grep '^3.4.312' | cut -d' ' -f4)"
done < "$OUT/candidates.txt"

echo '== candidate fold table =='
cat "$OUT/candidates.txt"
echo '== ASan 3.4.12 / 3.4.13 =='
cat "$OUT/asan.txt"
echo '== plain outcome counts (true / total) =='
for v in 3.4.12 3.4.13; do
  echo "-- $v"
  cut -d' ' -f1-4 "$OUT/plain-$v.txt" | sort | uniq -c
done
