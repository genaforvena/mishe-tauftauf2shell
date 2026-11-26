#!/bin/sh
# frontier lab runner — MuJS CVE-2026-110715, verbatim pinned upstream trees.
# Operator #5581 bounded experiment: ASan build, derived JS trigger, fixed and
# normal-sort controls. No socket, no admission claim, no wire/R4/R5 claim.
cd "$(dirname "$0")" || exit 2
printf 'var a=[3,1,2]; a.sort(); print("normal="+a.length+" "+a);\n' > harness/safe.js

VULN_TAR="src/mujs-v1.3.8.tar.gz"
FIX_TAR="src/mujs-fix.tar.gz"
VULN_TAR_SHA="8af271bda905241b7b64d73000924666d0fd297b72da316374afecb088e7616c"
FIX_TAR_SHA="26bd43fcff1d8d7888cb507dc4121b5af12b129162d979679fc682ee20c023d1"
VULN_SRC_SHA="d3bf5010e0f73621b599fcc9cdd9e6888c9bff24589d65a313dc37b695892472"
FIX_SRC_SHA="27361ae1d9f883164a71f0e7227d4ea3e4f378a5889a6f456ccdbc074e05792e"
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
expect_eq "vulnerable jsarray.c verbatim sha256" "$(sha build/vuln/jsarray.c)" "$VULN_SRC_SHA"
expect_eq "fixed jsarray.c verbatim sha256" "$(sha build/fixed/jsarray.c)" "$FIX_SRC_SHA"
DIFFLINES=$(diff -u build/vuln/jsarray.c build/fixed/jsarray.c | grep -c '^[+-][^+-]')
expect_eq "upstream diff touches 9 lines" "$DIFFLINES" "9"
hasnt build/vuln/jsarray.c 'idx_b < obj->u.a.flat_length' "vulnerable sort has no flat_length guard"
has build/fixed/jsarray.c 'idx_b < obj->u.a.flat_length' "fixed sort guards both simple-array branches"

for side in vuln fixed; do
    make -C "build/$side" HAVE_READLINE=no \
        CFLAGS='-std=c99 -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wall' \
        build/debug/mujs > "build/$side/make.log" 2>&1
    if [ "$?" -eq 0 ]; then ok "ASan build $side"; else bad "ASan build $side"; fi
done

# Derived trigger: length inflation leaves flat_length at 3 while length is 1000.
./build/vuln/build/debug/mujs harness/attack.js > build/vuln/attack.log 2>&1
VULN_RC=$?
has build/vuln/attack.log 'ERROR: AddressSanitizer: heap-buffer-overflow' "vuln ASan heap overflow"
has build/vuln/attack.log 'READ of size 1' "vuln ASan READ-1"
has build/vuln/attack.log 'Ap_sort_cmp /' "vuln ASan in Ap_sort_cmp"
has build/vuln/attack.log 'jsarray.c:246' "vuln ASan frame at verbatim jsarray.c:246"
if [ "$VULN_RC" -ne 0 ]; then ok "vuln ASan exits $VULN_RC"; else bad "vuln ASan nonzero exit"; fi

./build/fixed/build/debug/mujs harness/attack.js > build/fixed/attack.log 2>&1
FIXED_RC=$?
if [ "$FIXED_RC" -eq 0 ]; then ok "fixed attack clean exit"; else bad "fixed attack clean exit ($FIXED_RC)"; fi
has build/fixed/attack.log 'sorted-length=1000' "fixed build parses inflated length"
hasnt build/fixed/attack.log 'AddressSanitizer' "fixed no ASan report"

for side in vuln fixed; do
    ./build/$side/build/debug/mujs harness/safe.js > "build/$side/safe.log" 2>&1
    SAFE_RC=$?
    if [ "$SAFE_RC" -eq 0 ]; then ok "$side normal-sort clean exit"; else bad "$side normal-sort clean exit ($SAFE_RC)"; fi
    has "build/$side/safe.log" 'normal=3 1,2,3' "$side normal sort control"
    hasnt "build/$side/safe.log" 'AddressSanitizer' "$side normal sort no ASan report"
done

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
