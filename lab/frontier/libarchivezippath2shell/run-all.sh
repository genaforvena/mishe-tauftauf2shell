#!/bin/sh
# Frontier lab runner - libarchive CVE-2026-45308 / GHSA-xgqq-r5j8-3mch.
# Provisioning, local GCC ASan builds and locally crafted archives only.
# The shipped bsdtar CLI is the consumer; no socket, no external target.
set -u
cd "$(dirname "$0")" || exit 2

V_TAR=src/libarchive-3.8.7.tar.gz
F_TAR=src/libarchive-3.8.8.tar.gz
V_TAR_SHA=4b787cca6697a95c7725e45293c973c208cbdc71ae2279f30ef09f52472b9166
F_TAR_SHA=038918ea315cdd446cc63acfe880d6011832bbe1711c887de5de5441b306c190
PATCH_SHA=cb9a18bb9e733e6d4063b5f9d762401ce36dfd070b88827dc43774f832a49bad
GEN_SHA=97dd8da208989c522015d99cecbc27a95be053c62e351f5da043f28ddf7a3044
V_SRC_SHA=eafecfa369d89eedf26731332280f2759c66928ca26080e19ec764cbfa01c936
F_SRC_SHA=63ef63f7f65f1273abfd177b4d37e0a9767e727a4ed3901992984c10b3c0f1c3
PATCHED_SRC_SHA=09c204338ffea7eba194a6a5de7c09265815bb258934cc24214d61ebc0e9867b
SAFE_SHA=789ed4848784071f9f59c9c40ad7c6a87c0f1f13e1c75ec79615e861cf3011f2
EDGE_SHA=ddaf647493ef2138c4d07e22d8547950d8f514cb5ae4e50f2d62bd831ce7b2f0
POC_SHA=47f183663e98ce600de44352733ac090625312cba339304550401ca39c1f24e8
PASS=0
FAIL=0

sha() { sha256sum "$1" | cut -d' ' -f1; }
ok() { PASS=$((PASS + 1)); echo "PASS $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2' want '$3')"; fi; }
has() { if grep -qF "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -qF "$2" "$1"; then bad "$3"; else ok "$3"; fi; }

for pair in "$V_TAR:$V_TAR_SHA" "$F_TAR:$F_TAR_SHA" "src/fix.patch:$PATCH_SHA" "src/gen_tar.py:$GEN_SHA"; do
    f=${pair%%:*}
    h=${pair#*:}
    if [ -f "$f" ]; then expect_eq "pin $f" "$(sha "$f")" "$h"; else bad "pin $f present"; fi
done

rm -rf build out evidence
mkdir -p build out evidence
for side in vuln fixed; do
    if [ "$side" = vuln ]; then t=$V_TAR; else t=$F_TAR; fi
    mkdir -p build/$side build/patched
    tar xzf "$t" -C build/$side --strip-components=1 || bad "extract $t"
done
tar xzf "$V_TAR" -C build/patched --strip-components=1 || bad "extract patch target"
(cd build/patched && patch -p1 < ../../src/fix.patch > ../patch-apply.log 2>&1) \
    && ok "upstream fix patch applies cleanly to pinned 3.8.7" \
    || bad "upstream fix patch applies cleanly to pinned 3.8.7"
expect_eq "vulnerable zip.c hash" "$(sha build/vuln/libarchive/archive_write_set_format_zip.c)" "$V_SRC_SHA"
expect_eq "fixed zip.c hash" "$(sha build/fixed/libarchive/archive_write_set_format_zip.c)" "$F_SRC_SHA"
expect_eq "patched-3.8.7 zip.c hash" "$(sha build/patched/libarchive/archive_write_set_format_zip.c)" "$PATCHED_SRC_SHA"
hasnt build/vuln/libarchive/archive_write_set_format_zip.c 'Pathname too long' "vuln lacks length guard"
has build/fixed/libarchive/archive_write_set_format_zip.c 'Pathname too long' "fixed has length guard"
has build/patched/libarchive/archive_write_set_format_zip.c 'Pathname too long' "patched 3.8.7 has length guard"

for side in vuln fixed; do
    (cd build/$side && \
        ./configure --disable-shared --enable-static \
            CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer' \
            LDFLAGS='-fsanitize=address' > ../configure-$side.log 2>&1 && \
        make -j6 > ../make-$side.log 2>&1) \
        && ok "GCC ASan build $side" || bad "GCC ASan build $side"
done

python3 src/gen_tar.py out/safe.tar 65535 && python3 src/gen_tar.py out/edge.tar 65537 \
    && python3 src/gen_tar.py out/poc.tar 131072 || bad "craft PAX tars"
expect_eq "safe tar hash" "$(sha out/safe.tar)" "$SAFE_SHA"
expect_eq "edge tar hash" "$(sha out/edge.tar)" "$EDGE_SHA"
expect_eq "poc tar hash" "$(sha out/poc.tar)" "$POC_SHA"

for f in safe edge poc; do
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
        ./build/vuln/bsdtar --format=zip -cf out/vuln-$f.zip @out/$f.tar \
        > out/vuln-$f.stdout 2> evidence/vuln-$f.err
    V_RC=$?
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
        ./build/fixed/bsdtar --format=zip -cf out/fixed-$f.zip @out/$f.tar \
        > out/fixed-$f.stdout 2> evidence/fixed-$f.err
    F_RC=$?
    if [ "$f" = safe ]; then
        if [ "$V_RC" -eq 0 ]; then ok "vuln safe rc0"; else bad "vuln safe rc0 ($V_RC)"; fi
        hasnt evidence/vuln-$f.err 'AddressSanitizer' "vuln safe ASan clean"
        hasnt evidence/fixed-$f.err 'AddressSanitizer' "fixed safe ASan clean"
        hasnt evidence/fixed-$f.err 'Pathname too long' "fixed safe no rejection"
        if [ "$(stat -c%s out/vuln-$f.zip)" -gt 22 ]; then ok "vuln safe produced ZIP"; else bad "vuln safe produced ZIP"; fi
    else
        has evidence/vuln-$f.err 'AddressSanitizer: heap-buffer-overflow' "vuln $f heap overflow"
        has evidence/vuln-$f.err "WRITE of size $([ "$f" = edge ] && echo 65537 || echo 131072)" "vuln $f write size"
        has evidence/vuln-$f.err 'copy_path libarchive/archive_write_set_format_zip.c:2328' "vuln $f verbatim sink"
        has evidence/vuln-$f.err 'archive_write_zip_header libarchive/archive_write_set_format_zip.c:1193' "vuln $f shipped caller"
        has evidence/vuln-$f.err '0 bytes after 65536-byte region' "vuln $f exact boundary"
        has evidence/fixed-$f.err 'Pathname too long for ZIP format' "fixed $f rejects path"
        hasnt evidence/fixed-$f.err 'AddressSanitizer' "fixed $f ASan clean"
        expect_eq "fixed $f ZIP size" "$(stat -c%s out/fixed-$f.zip)" "22"
    fi
    if [ "$F_RC" -eq 0 ]; then ok "fixed $f rc0"; else bad "fixed $f rc0 ($F_RC)"; fi
done

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
