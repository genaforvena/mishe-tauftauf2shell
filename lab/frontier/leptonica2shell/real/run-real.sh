#!/usr/bin/env bash
# Real Leptonica 1.87.0 / fix c493a776 l_byteaInitFromFile() replay.
# Build both trees with ASan first (see real/README.md); all inputs local.
set -u
cd "$(dirname "$0")"
mkdir -p out evidence

BIG=evidence/sparse-big.bin
SAFE=evidence/safe-16.bin
truncate -s 1000000001 "$BIG"
printf 'MISHE-LEPTONICA' | dd of="$BIG" bs=1 seek=201 conv=notrunc status=none
printf 'MISHE-LEPTONICA\0' > "$SAFE"

CF="-O0 -g -fno-omit-frame-pointer -fsanitize=address -DHAVE_CONFIG_H"
inc_v="-I src/src -I build-vuln/src"
inc_f="-I src-fixed/src -I build-fixed/src"
gcc $CF $inc_v -o out/real-vuln realfile.c build-vuln/src/libleptonica.a -lm || exit 2
gcc $CF $inc_f -o out/real-fixed realfile.c build-fixed/src/libleptonica.a -lm || exit 2
gcc $CF $inc_v -o out/real-caller caller.c build-vuln/src/libleptonica.a -lm || exit 2

PASS=0; FAIL=0
ok() { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }

printf '== real vulnerable 1.87.0, oversized file\n'
A=$(out/real-vuln "$BIG" 2>&1); RC=$?
printf '%s\n' "$A" > evidence/real-vuln-asan.out
case "$A" in
  *'heap-buffer-overflow'*'WRITE of size 1000000001'*'0 bytes after 201-byte region'*)
    ok 'real ASan WRITE of size 1000000001 past 201-byte region';;
  *) bad "real ASan WRITE (rc=$RC)";;
esac
case "$A" in
  *'bytearray.c:1'*'l_byteaInitFromStream'*) ok 'real stack in pinned l_byteaInitFromStream';;
  *) bad 'real ASan stack';;
esac
case "$A" in
  *'bytearray.c:1'*'l_byteaCreate'*) ok 'real allocation in pinned l_byteaCreate';;
  *) bad 'real ASan allocation frame';;
esac

printf '== real vulnerable 1.87.0, in-library caller saConcatenatePdfToData\n'
C=$(out/real-caller "$BIG" 2>&1); RC=$?
printf '%s\n' "$C" > evidence/real-caller-asan.out
case "$C" in
  *'heap-buffer-overflow'*'WRITE of size 1000000001'*) ok 'caller path reaches real ASan WRITE';;
  *) bad "caller path ASan WRITE (rc=$RC)";;
esac
case "$C" in
  *'l_byteaInitFromStream'*'l_byteaInitFromFile'*'saConcatenatePdfToData'*)
    ok 'caller stack through pdfio1.c into pinned function';;
  *) bad 'caller stack frames';;
esac

printf '== real fixed commit c493a776, oversized file\n'
F=$(out/real-fixed "$BIG" 2>&1); RC=$?
printf '%s\n' "$F" > evidence/real-fixed-asan.out
case "$F" in
  *AddressSanitizer*) bad 'fixed real ASan attack must be clean';;
  *'BA=NULL'*) [ "$RC" -eq 0 ] && ok 'fixed real library rejects oversized file' || bad "fixed rc=$RC";;
  *) bad 'fixed real library result';;
esac

printf '== real vulnerable 1.87.0, safe 16-byte file\n'
S=$(out/real-vuln "$SAFE" 2>&1); RC=$?
printf '%s\n' "$S" > evidence/real-vuln-safe.out
case "$S" in
  *AddressSanitizer*) bad 'vulnerable real safe input ASan';;
  *'SIZE=16'*) [ "$RC" -eq 0 ] && ok 'safe 16-byte real input clean' || bad "safe rc=$RC";;
  *) bad 'safe real input shape';;
esac

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
