#!/bin/sh
# Frontier lab runner - ntfs-3g CVE-2026-42618, verbatim pinned 2026.2.25 tag.
# Provisioning, local GCC ASan builds and a loopback file image only: no socket,
# no mount, no external target. The shipped ntfscat CLI is the consumer.
set -u
cd "$(dirname "$0")" || exit 2

TAR=src/ntfs-3g_ntfsprogs-2026.2.25.tgz
TAR_URL=https://tuxera.com/opensource/ntfs-3g_ntfsprogs-2026.2.25.tgz
TAR_SHA=7754f3b32e8baf9c472459b4e9c981e3ae0f5039107cdd8d8201aed0a949008a
PATCH_SHA=6a53ca72ae9275cb4dca0ee4b84a61ff299cbed1225dd582d9092070a358eb3f
GEN_SHA=309b3a9d1239897d66a9c049dbd4b80a2d0061a2db516c595ea184536d80059f
VULN_SRC_SHA=003f0ebb258cb40a53677911897d30e1d15c368530083d564a05434ec130ae89
FIXED_SRC_SHA=c15b75ea36f3ccdf7662b37e6752d37075f54c42453d76a80435bb209fe67771
BASE_SHA=c9d04e71517b3f31f7e32eb1d91e3e4745931ad643bb82fe4074a9cf26cd6cef
POC_SHA=4b049df8f875be4e0f62d451d592f38a13c8e8a4f4b12fdb5eed63250dea6b62
SAFE_SHA=c4498b789d8bdff57b30d2e500ae72b61a14f27af9f294c9920f1f2c083b0b29
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
expect_eq "vendor fix patch sha256" "$(sha src/vendor-fix.patch)" "$PATCH_SHA"
expect_eq "image generator sha256" "$(sha src/gen_image.py)" "$GEN_SHA"

rm -rf build out evidence
mkdir -p build/vuln build/fixed out evidence
tar xzf "$TAR" -C build/vuln --strip-components=1 || bad "extract pinned tarball"
cp -a build/vuln/. build/fixed/ || bad "copy fixed tree"
(cd build/fixed && patch -p1 < ../../src/vendor-fix.patch > ../fix-apply.log 2>&1) \
    && ok "single vendor patch applies" || bad "single vendor patch applies"
expect_eq "vulnerable compress.c sha256" "$(sha build/vuln/libntfs-3g/compress.c)" "$VULN_SRC_SHA"
expect_eq "fixed compress.c sha256" "$(sha build/fixed/libntfs-3g/compress.c)" "$FIXED_SRC_SHA"

for side in vuln fixed; do
    (cd "build/$side" && CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer' \
        LDFLAGS='-fsanitize=address' ./configure --disable-shared \
        > "../$side-configure.log" 2>&1) \
        && ok "configure $side" || bad "configure $side"
    (cd "build/$side" && make -j4 > "../$side-make.log" 2>&1) \
        && ok "GCC ASan build $side" || bad "GCC ASan build $side"
done

truncate -s 4M out/base.img
ASAN_OPTIONS=detect_leaks=0 ./build/vuln/ntfsprogs/mkntfs \
    -F -f -q -T -c 4096 out/base.img > out/mkntfs.log 2>&1 \
    && ok "pinned mkntfs bootstrap" || bad "pinned mkntfs bootstrap"
expect_eq "deterministic base image sha256" "$(sha out/base.img)" "$BASE_SHA"

python3 src/gen_image.py out/base.img out/poc.img || bad "craft poc image"
python3 src/gen_image.py out/base.img out/safe.img safe || bad "craft safe image"
expect_eq "poc image sha256" "$(sha out/poc.img)" "$POC_SHA"
expect_eq "safe image sha256" "$(sha out/safe.img)" "$SAFE_SHA"

# Vulnerable build, crafted image: shipped CLI reaches ntfs_decompress().
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build/vuln/ntfsprogs/ntfscat -f -i 16 out/poc.img \
    > out/vuln-poc.stdout 2> evidence/vuln-poc.err
VULN_RC=$?
has evidence/vuln-poc.err 'ERROR: AddressSanitizer: heap-buffer-overflow' "vuln ASan heap overflow"
has evidence/vuln-poc.err 'WRITE of size 1' "vuln WRITE-1"
has evidence/vuln-poc.err 'compress.c:568' "verbatim vulnerable source line"
has evidence/vuln-poc.err 'ntfs_compressed_attr_pread' "compressed-read caller frame"
has evidence/vuln-poc.err 'ntfscat.c:371' "shipped CLI cat loop frame"
has evidence/vuln-poc.err '0 bytes after 65536-byte region' "exact heap boundary"
if [ "$VULN_RC" -ne 0 ]; then ok "vuln ASan exits $VULN_RC"; else bad "vuln ASan nonzero exit"; fi
expect_eq "vuln stdout before abort" "$(stat -c%s out/vuln-poc.stdout)" "61440"

# Vendor-patched build, same crafted image.
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build/fixed/ntfsprogs/ntfscat -f -i 16 out/poc.img \
    > out/fixed-poc.stdout 2> evidence/fixed-poc.err
FIXED_RC=$?
hasnt evidence/fixed-poc.err 'AddressSanitizer' "fixed no ASan report"
if [ "$FIXED_RC" -eq 0 ]; then ok "fixed clean exit"; else bad "fixed clean exit ($FIXED_RC)"; fi
expect_eq "fixed stdout length" "$(stat -c%s out/fixed-poc.stdout)" "65536"

# Safe input on both builds: no stray literal tokens after a full sub-block.
for side in vuln fixed; do
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
        "./build/$side/ntfsprogs/ntfscat" -f -i 16 out/safe.img \
        > "out/$side-safe.stdout" 2> "evidence/$side-safe.err"
    RC=$?
    hasnt "evidence/$side-safe.err" 'AddressSanitizer' "$side safe no ASan"
    if [ "$RC" -eq 0 ]; then ok "$side safe clean exit"; else bad "$side safe clean exit ($RC)"; fi
    expect_eq "$side safe stdout length" "$(stat -c%s out/$side-safe.stdout)" "65536"
done

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
