#!/bin/sh
# frontier lab runner — libsmpp34 CVE-2026-75895, verbatim pinned upstream source.
# No upstream source line is edited. No socket, no external target.
set -u
cd "$(dirname "$0")" || exit 2

VULN_TAR="src/libsmpp34-1.14.5.tar.gz"
FIX_TAR="src/libsmpp34-1.14.6.tar.gz"
VULN_TAR_SHA="6a275907cd72db49aca1519a2df061869be280862fb2ce7395055f17e366d6e3"
FIX_TAR_SHA="c85f8d09522b6600a51a2fb28d2872baceb5fd00f7dd119437d05a1aafc5a1ab"
VULN_SRC_SHA="37c0a175455dbc1bf03de5ecc2607e902522cc2562e6abe6b6192c0da091585e"
FIX_SRC_SHA="9863e806952cd7381c7dbc4bbb31736395cdb0bfb36985ae178ce028ec0032f8"
VULN_PREFIX="libsmpp34-d6ac32fde99f08b2019a5ca095471456583dc93a"
FIX_PREFIX="libsmpp34-f93991bd19b6715a6e1782711734cfc52760432e"
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
for side in vuln fixed; do
    if [ "$side" = vuln ]; then prefix="$VULN_PREFIX"; tar="$VULN_TAR"; else prefix="$FIX_PREFIX"; tar="$FIX_TAR"; fi
    tar xzf "$tar" -C "build/$side" --strip-components=1 \
        "$prefix/src/smpp34_unpack.c" "$prefix/src/smpp34_structs.c" \
        "$prefix/src/smpp34_params.c" "$prefix/src/smpp34_heap.c" \
        "$prefix/src/smpp34.h" "$prefix/src/smpp34_structs.h" \
        "$prefix/src/smpp34_params.h" "$prefix/src/smpp34_heap.h" \
        "$prefix/def_frame" "$prefix/def_list" || bad "extract $side"
done
expect_eq "vulnerable smpp34_unpack.c verbatim sha256" "$(sha build/vuln/src/smpp34_unpack.c)" "$VULN_SRC_SHA"
expect_eq "fixed smpp34_unpack.c verbatim sha256" "$(sha build/fixed/src/smpp34_unpack.c)" "$FIX_SRC_SHA"
DIFFLINES=$(diff build/vuln/src/smpp34_unpack.c build/fixed/src/smpp34_unpack.c | grep -c '^[<>]')
expect_eq "upstream diff changes exactly one line pair" "$DIFFLINES" "2"
has build/vuln/src/smpp34_unpack.c 'lenval = strlen' "vulnerable line is unbounded strlen"
has build/fixed/src/smpp34_unpack.c 'strnlen((char *)aux, left)' "fixed line is bounded strnlen"

for side in vuln fixed; do
    common="-std=c99 -O0 -g -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L -I build/$side/src -I build/$side"
    srcs="harness/driver.c build/$side/src/smpp34_unpack.c build/$side/src/smpp34_structs.c build/$side/src/smpp34_params.c build/$side/src/smpp34_heap.c"
    # shellcheck disable=SC2086
    gcc $common -fsanitize=address -o "build/$side/asan" $srcs || bad "gcc asan build $side"
    # shellcheck disable=SC2086
    clang $common -fsanitize=address -o "build/$side/clang" $srcs || bad "clang asan build $side"
done
gcc -std=c99 -O0 -g -D_POSIX_C_SOURCE=200809L -I build/vuln/src -I build/vuln \
    -o build/vuln/plain harness/driver.c build/vuln/src/smpp34_unpack.c \
    build/vuln/src/smpp34_structs.c build/vuln/src/smpp34_params.c \
    build/vuln/src/smpp34_heap.c || bad "plain build"

# Rung 2/3: 17-byte heap PDU (16-byte header + one unterminated C-Octet).
./build/vuln/asan attack > build/vuln/asan-attack.log 2>&1
VULN_RC=$?
has build/vuln/asan-attack.log 'ERROR: AddressSanitizer: heap-buffer-overflow' "gcc vuln ASan heap overflow"
has build/vuln/asan-attack.log 'READ of size 2' "gcc vuln ASan READ size 2"
has build/vuln/asan-attack.log '0 bytes after 17-byte region' "gcc vuln ASan exact allocation boundary"
has build/vuln/asan-attack.log 'smpp34_unpack build/vuln/def_frame/bind_transmitter.frame:1' "gcc vuln ASan frame at verbatim bind frame"
if [ "$VULN_RC" -ne 0 ]; then ok "gcc vuln ASan exits $VULN_RC"; else bad "gcc vuln ASan nonzero exit"; fi

./build/vuln/clang attack > build/vuln/clang-attack.log 2>&1
CLANG_RC=$?
has build/vuln/clang-attack.log 'ERROR: AddressSanitizer: heap-buffer-overflow' "clang vuln ASan heap overflow"
has build/vuln/clang-attack.log 'READ of size 2' "clang vuln ASan READ size 2"
has build/vuln/clang-attack.log 'bind_transmitter.frame:1' "clang vuln ASan frame at verbatim bind frame"
if [ "$CLANG_RC" -ne 0 ]; then ok "clang vuln ASan exits $CLANG_RC"; else bad "clang vuln ASan nonzero exit"; fi

# Fixed build rejects the same PDU after the bounded scan; no ASan report.
./build/fixed/asan attack > build/fixed/asan-attack.log 2>&1
FIXED_RC=$?
if [ "$FIXED_RC" -eq 0 ]; then ok "fixed ASan clean exit"; else bad "fixed ASan clean exit ($FIXED_RC)"; fi
has build/fixed/asan-attack.log 'MODE=attack LEN=17 rv=-1' "fixed rejects unterminated C-Octet"
has build/fixed/asan-attack.log 'len(system_id):2(Value length exceed buffer length)' "fixed strnlen length guard fires"
hasnt build/fixed/asan-attack.log 'AddressSanitizer' "fixed no ASan report"
./build/fixed/clang attack > build/fixed/clang-attack.log 2>&1
if [ "$?" -eq 0 ] && ! grep -q AddressSanitizer build/fixed/clang-attack.log; then
    ok "clang fixed attack clean"
else
    bad "clang fixed attack clean"
fi

# Safe controls: complete, valid bind_transmitter with terminated C-Octets.
for side in vuln fixed; do
    ./build/$side/asan safe-full > "build/$side/asan-safe-full.log" 2>&1
    SAFE_RC=$?
    if [ "$SAFE_RC" -eq 0 ]; then ok "$side ASan valid PDU clean exit"; else bad "$side ASan valid PDU clean exit ($SAFE_RC)"; fi
    has "build/$side/asan-safe-full.log" 'MODE=safe-full LEN=31 rv=0' "$side valid PDU parsed"
    has "build/$side/asan-safe-full.log" 'system_id=sys password=pw address_range=r' "$side chosen bytes read back"
    hasnt "build/$side/asan-safe-full.log" 'AddressSanitizer' "$side valid PDU no ASan report"
done

# Guard-page control: the unterminated byte is the last byte before PROT_NONE.
./build/vuln/plain guard > build/vuln/plain-guard.log 2>&1
GUARD_RC=$?
expect_eq "plain guard-page fault rc" "$GUARD_RC" "139"
has build/vuln/plain-guard.log 'MODE=guard LEN=17' "guard-page input reached unpack"

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
