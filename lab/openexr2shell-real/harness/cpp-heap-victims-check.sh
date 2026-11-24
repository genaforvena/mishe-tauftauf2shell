#!/bin/sh
# W182: one-command replay of the 4096-byte sink's heap layout on the C++
# DeepScanLineInputFile::readPixels path (W171 measured only the flat exrcheck
# path). No wire, no chosen bytes, no pointer control: this maps whether the
# overwritten range contains a live code pointer or vtable. It does not.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

python3 cases/make_poc.py cases/baseline.exr cases/poc.exr >/dev/null
test "$(sha256sum cases/poc.exr | cut -d' ' -f1)" = \
    283cec0e18532c500495e71496145832d36dbfc502e44f490e09114661ab37ce

gdb -q -batch -x harness/cpp-heap-victims.cmd \
    bin-vuln-plain/cpp_singlepass 2>&1 \
    | grep -E '^(SINK| PTR-| CHUNK| LIVE-| HDR-| END-PY|READPIXELS|cases/poc)' \
    > evidence/cpp-heap-victims.out

bin-vuln-plain/cpp_singlepass cases/baseline.exr > evidence/cpp-heap-baseline.out 2>&1 || true
bin-fixed-asan/cpp_singlepass cases/poc.exr > evidence/cpp-heap-fixed.out 2>&1 || true
grep -Fqx 'SINK n=4096 src_minus_dst=101584' evidence/cpp-heap-victims.out
grep -Fqx ' PTR-HITS total=0' evidence/cpp-heap-victims.out
grep -Fqx ' CHUNK-COUNT total=3 first_off=64' evidence/cpp-heap-victims.out
grep -Fqx ' CHUNK off=+112 size=0x1490 hdr=0x1491' evidence/cpp-heap-victims.out
grep -Fqx ' LIVE-PTR-COUNT scanned=33 inside=3' evidence/cpp-heap-victims.out
grep -Fqx ' LIVE-PTR-INSIDE exr_decoding_run.decode.unpacked_buffer off=+0' evidence/cpp-heap-victims.out
grep -Fqx ' HDR-CORRUPTED 2/3' evidence/cpp-heap-victims.out
grep -Fqx 'READPIXELS exception: Unable to run decoder' evidence/cpp-heap-victims.out
grep -Fqx 'READPIXELS ok rv=0' evidence/cpp-heap-baseline.out
grep -Fq 'EXR_ERR_CORRUPT_CHUNK' evidence/cpp-heap-fixed.out

echo RESULT PASS
sha256sum evidence/cpp-heap-victims.out evidence/cpp-heap-baseline.out \
    evidence/cpp-heap-fixed.out
