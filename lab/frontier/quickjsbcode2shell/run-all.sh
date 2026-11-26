#!/bin/sh
# frontier lab runner — bellard/quickjs CVE-2026-88378, verbatim pinned commits.
# No upstream source line is edited. No socket, no external target.
set -u
cd "$(dirname "$0")" || exit 2

VULN_TAR="src/quickjs-vuln.tar.gz"
FIX_TAR="src/quickjs-fixed.tar.gz"
VULN_TAR_SHA="2a87ffcca6c870f764ce70a7736351bd7cff3dc1fb95a8fb059c260979f1e01a"
FIX_TAR_SHA="bd32b79944dc7a46fcebaf144eedbe4d76eeca4ec102043863ee46d224d561b2"
VULN_SRC_SHA="a68622cecb806f39bf24738c376a0a73032ea8913478cad702e0265c46f7999f"
FIX_SRC_SHA="c228e1c185faca75bb5764c211d35b0d3901cdafe7293491917fdb9350fe68b8"
PASS=0
FAIL=0

sha() { sha256sum "$1" | cut -d' ' -f1; }
ok() { PASS=$((PASS + 1)); echo "PASS $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2' want '$3')"; fi; }
has() { if grep -qF "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -qF "$2" "$1"; then bad "$3"; else ok "$3"; fi; }

expect_eq "vulnerable tarball sha256" "$(sha "$VULN_TAR")" "$VULN_TAR_SHA"
expect_eq "fixed tarball sha256" "$(sha "$FIX_TAR")" "$FIX_TAR_SHA"

rm -rf build
mkdir -p build/vuln build/fixed
tar xzf "$VULN_TAR" -C build/vuln --strip-components=1 || bad "extract vuln"
tar xzf "$FIX_TAR" -C build/fixed --strip-components=1 || bad "extract fixed"
expect_eq "vulnerable quickjs.c verbatim sha256" "$(sha build/vuln/quickjs.c)" "$VULN_SRC_SHA"
expect_eq "fixed quickjs.c verbatim sha256" "$(sha build/fixed/quickjs.c)" "$FIX_SRC_SHA"
DIFFLINES=$(diff -u build/vuln/quickjs.c build/fixed/quickjs.c | grep -c '^[+-][^+-]')
expect_eq "upstream diff touches 13 lines in one function" "$DIFFLINES" "13"
has build/vuln/quickjs.c 'return bc_get_leb128(s, (uint32_t *)pval);' "vulnerable cast-through-int present"
has build/fixed/quickjs.c 'val > INT_MAX' "fixed INT_MAX guard present"
has build/fixed/quickjs.c 'integer overflow while reading bytecode' "fixed SyntaxError present"

for side in vuln fixed; do
    VER=$(cat "build/$side/VERSION")
    SRC="harness/driver.c build/$side/quickjs.c build/$side/dtoa.c build/$side/libregexp.c build/$side/libunicode.c build/$side/cutils.c"
    # shellcheck disable=SC2086
    gcc -std=gnu99 -O0 -g -fno-omit-frame-pointer -fsanitize=address \
        -D_GNU_SOURCE "-DCONFIG_VERSION=\"$VER\"" -include limits.h \
        -I "build/$side" -o "build/$side/asan" $SRC -lm -ldl -lpthread \
        || bad "gcc asan build $side"
done
VER=$(cat build/vuln/VERSION)
SRC="harness/driver.c build/vuln/quickjs.c build/vuln/dtoa.c build/vuln/libregexp.c build/vuln/libunicode.c build/vuln/cutils.c"
# shellcheck disable=SC2086
clang -std=gnu99 -O0 -g -fno-omit-frame-pointer -fsanitize=address \
    -D_GNU_SOURCE "-DCONFIG_VERSION=\"$VER\"" -include limits.h \
    -I build/vuln -o build/vuln/clang $SRC -lm -ldl -lpthread \
    || bad "clang asan build vuln"

# Rung 3: exact upstream 21-byte regression input through JS_ReadObject().
./build/vuln/asan attack > build/vuln/asan-attack.log 2>&1
VULN_RC=$?
has build/vuln/asan-attack.log 'ERROR: AddressSanitizer: heap-buffer-overflow' "gcc vuln ASan heap overflow"
has build/vuln/asan-attack.log 'WRITE of size 96' "gcc vuln ASan WRITE size 96"
has build/vuln/asan-attack.log 'JS_ReadFunctionTag build/vuln/quickjs.c:38820' "gcc vuln ASan frame at verbatim quickjs.c:38820"
has build/vuln/asan-attack.log '0 bytes after 88-byte region' "gcc vuln ASan exact allocation boundary"
if [ "$VULN_RC" -ne 0 ]; then ok "gcc vuln ASan exits $VULN_RC"; else bad "gcc vuln ASan nonzero exit"; fi

# Fixed build rejects the same bytes with a SyntaxError; no ASan report.
./build/fixed/asan attack > build/fixed/asan-attack.log 2>&1
FIXED_RC=$?
if [ "$FIXED_RC" -eq 0 ]; then ok "fixed ASan clean exit"; else bad "fixed ASan clean exit ($FIXED_RC)"; fi
has build/fixed/asan-attack.log 'exception=SyntaxError: integer overflow while reading bytecode' "fixed rejects overflowing count"
hasnt build/fixed/asan-attack.log 'AddressSanitizer' "fixed no ASan report"

# Clang 18 is silent on this input — preserved negative, not a pass for the bug.
./build/vuln/clang attack > build/vuln/clang-attack.log 2>&1
CLANG_RC=$?
if [ "$CLANG_RC" -eq 0 ] && ! grep -q AddressSanitizer build/vuln/clang-attack.log; then
    ok "clang vuln silent (documented compiler-negative)"
else
    bad "clang vuln silent (documented compiler-negative)"
fi

# Safe control: real bytecode is written, read back and evaluated to 2.
for side in vuln fixed; do
    ./build/$side/asan safe-bytecode > "build/$side/asan-safe.log" 2>&1
    SAFE_RC=$?
    if [ "$SAFE_RC" -eq 0 ]; then ok "$side ASan safe bytecode clean exit"; else bad "$side ASan safe bytecode clean exit ($SAFE_RC)"; fi
    has "build/$side/asan-safe.log" 'read_exception=0' "$side valid bytecode parsed"
    has "build/$side/asan-safe.log" 'value=2' "$side valid bytecode evaluated"
    hasnt "build/$side/asan-safe.log" 'AddressSanitizer' "$side valid bytecode no ASan report"
done

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
