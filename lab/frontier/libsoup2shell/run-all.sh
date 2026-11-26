#!/bin/sh
# libsoup CVE-2026-102555 lab runner. Compiles the VERBATIM pinned
# libsoup/soup-uri-utils.c from the vuln/fixed worktrees, links a lab-only
# driver, and checks the stale-length over-read plus fixed/safe controls.
# No network, no socket, no live target, no command execution.
set -u
cd "$(dirname "$0")" || exit 1
BUILD=build
mkdir -p "$BUILD"
PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
expect() { # name, pattern, file
    if grep -q "$2" "$3"; then ok "$1"; else bad "$1"; fi
}
refuse() { # name, file, pattern
    if grep -q "$2" "$3"; then bad "$1"; else ok "$1"; fi
}

VULN_SHA=45e37054e8d06e2c8cfa1cc3e0da7780575f01926e8ee7c2d0c04dea0b3d82b7
FIXED_SHA=77d21acf5f769a6e92a641a16f2754d162ec7b766e84189f98e8d1e66158fd5d
vsha=$(sha256sum vuln/libsoup/soup-uri-utils.c | cut -d' ' -f1)
fsha=$(sha256sum fixed/libsoup/soup-uri-utils.c | cut -d' ' -f1)
[ "$vsha" = "$VULN_SHA" ] && ok 'vuln pin sha256' || bad 'vuln pin sha256'
[ "$fsha" = "$FIXED_SHA" ] && ok 'fixed pin sha256' || bad 'fixed pin sha256'
cp vuln/libsoup/soup-uri-utils.c "$BUILD/soup-uri-utils-vuln.c"
cp fixed/libsoup/soup-uri-utils.c "$BUILD/soup-uri-utils-fixed.c"

GLIB_CFLAGS=$(pkg-config --cflags glib-2.0 gio-2.0 gobject-2.0) || exit 1
GLIB_LIBS=$(pkg-config --libs glib-2.0 gio-2.0 gobject-2.0) || exit 1
CFLAGS="-fno-omit-frame-pointer -g -O0 -DGETTEXT_PACKAGE=\"libsoup-3.0\" -I shim"
INC_V="-I vuln/libsoup -I vuln"
INC_F="-I fixed/libsoup -I fixed"
ASAN="-fsanitize=address"
ASANOPTS='detect_leaks=0:detect_stack_use_after_return=0'

compile() { # label, compiler, extra flags, source, tree includes, driver obj, out
    $2 $3 $CFLAGS $5 $GLIB_CFLAGS -c "$4" -o "$BUILD/$1-src.o" 2>"$BUILD/$1-cc.log" || return 1
    $2 $3 -g -O0 $GLIB_CFLAGS -c harness/driver.c -o "$BUILD/$1-driver.o" 2>>"$BUILD/$1-cc.log" || return 1
    $2 $3 "$BUILD/$1-src.o" "$BUILD/$1-driver.o" $GLIB_LIBS -o "$BUILD/$1" 2>>"$BUILD/$1-cc.log"
}
if compile gccvuln gcc "$ASAN" "$BUILD/soup-uri-utils-vuln.c" "$INC_V" "$BUILD/gccvuln"; then ok 'gcc ASan vuln build'; else bad 'gcc ASan vuln build'; fi
if compile clangvuln clang "$ASAN" "$BUILD/soup-uri-utils-vuln.c" "$INC_V" "$BUILD/clangvuln"; then ok 'clang ASan vuln build'; else bad 'clang ASan vuln build'; fi
if compile gccfixed gcc "$ASAN" "$BUILD/soup-uri-utils-fixed.c" "$INC_F" "$BUILD/gccfixed"; then ok 'gcc ASan fixed build'; else bad 'gcc ASan fixed build'; fi
if compile plain gcc "" "$BUILD/soup-uri-utils-vuln.c" "$INC_V" "$BUILD/plain"; then ok 'plain vuln build'; else bad 'plain vuln build'; fi

ASAN_OPTIONS=$ASANOPTS "$BUILD/gccvuln" >"$BUILD/gccvuln-fresh.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/clangvuln" groom 1024 >"$BUILD/clangvuln-groom.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/gccvuln" groom 1024 >"$BUILD/gccvuln-groom1024.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/gccfixed" groom 1024 >"$BUILD/gccfixed-groom.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/gccvuln" safe >"$BUILD/gccvuln-safe.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/gccfixed" safe >"$BUILD/gccfixed-safe.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/gccvuln" glib-probe >"$BUILD/glib-probe.log" 2>&1 || true
"$BUILD/plain" groom 1024 >"$BUILD/plain-groom.log" 2>&1
plain_rc=$?

expect 'GLib precondition fails on embedded NUL' 'assertion .input_length > 1. failed' "$BUILD/glib-probe.log"
expect 'GLib leaves out length untouched' 'out=4702111234474983745' "$BUILD/glib-probe.log"
expect 'gcc ASan heap READ after 128-byte region' '0 bytes after 128-byte region' "$BUILD/gccvuln-groom1024.log"
expect 'gcc ASan READ of size 1' 'READ of size 1' "$BUILD/gccvuln-groom1024.log"
expect 'gcc ASan allocation via g_uri_unescape_bytes' 'g_uri_unescape_bytes' "$BUILD/gccvuln-groom1024.log"
expect 'gcc ASan stack names pinned decoder line 405' 'soup-uri-utils-vuln.c:405' "$BUILD/gccvuln-groom1024.log"
expect 'gcc ASan heap READ in fresh process' 'ERROR: AddressSanitizer: heap-buffer-overflow' "$BUILD/gccvuln-fresh.log"
expect 'fixed build clean under stale-length sequence' 'READ_OK bytes=0 sum=0' "$BUILD/gccfixed-groom.log"
refuse 'fixed build has no ASan report' 'ERROR: AddressSanitizer' "$BUILD/gccfixed-groom.log"
expect 'safe inputs decode cleanly in vulnerable build' 'READ_OK bytes=5 sum=532' "$BUILD/gccvuln-safe.log"
refuse 'safe vectors no ASan report' 'ERROR: AddressSanitizer' "$BUILD/gccvuln-safe.log"
expect 'fixed vector differs: full hello decoded' 'READ_OK bytes=5 sum=532' "$BUILD/gccfixed-safe.log"
if [ "$plain_rc" -ne 0 ]; then ok 'plain build nonzero rc'; else bad 'plain build nonzero rc'; fi

printf 'RESULT PASS=%d FAIL=%d plain_rc=%d\n' "$PASS" "$FAIL" "$plain_rc"
[ "$FAIL" -eq 0 ]
