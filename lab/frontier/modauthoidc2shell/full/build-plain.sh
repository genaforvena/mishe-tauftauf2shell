#!/usr/bin/env bash
# Build the "plain" full module to observe the OOB NUL store on the live wire.
# W14: apxs from this ASan httpd injects -fsanitize=address, so the module is
# ASan-instrumented and links libasan; "plain" is only a build label.
# Reuses the pinned sources and the plain httpd 2.4.70 / APR stack. Loopback only.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$HERE/../../apache2shell/build"
P="$HERE/plain-prefix"
SRC="$HERE/src/mod_auth_openidc"
PLAIN="$HERE/src/mod_auth_openidc-plain"
APXS="$B/httpd-2.4.70-install/bin/apxs"
mkdir -p "$P" "$HERE/evidence"

if [ ! -d "$PLAIN" ]; then
    git -C "$SRC" worktree add -q "$PLAIN" 4301b5364034191adcba5153e5870405855cb74e
fi
echo "PIN: $(sha256sum "$PLAIN/src/state.c")"

export PKG_CONFIG_PATH="$P/lib/pkgconfig"

if [ ! -f "$P/lib/libjansson.so" ] || [ -n "${FORCE_DEPS:-}" ]; then
    cd "$HERE/src/jansson-2.14"
    make clean >/dev/null 2>&1 || true
    ./configure --prefix="$P" CFLAGS='-O1 -g' \
      >"$HERE/evidence/plain-jansson-configure.log" 2>&1
    make -j4 >"$HERE/evidence/plain-jansson-build.log" 2>&1
    make install >>"$HERE/evidence/plain-jansson-build.log" 2>&1
fi

if [ ! -f "$P/lib/libcjose.so" ] || [ -n "${FORCE_DEPS:-}" ]; then
    cd "$HERE/src/cjose-0.6.1"
    make clean >/dev/null 2>&1 || true
    ./configure --prefix="$P" --with-jansson="$P" --with-openssl=/usr \
      CFLAGS='-O1 -g -Wno-error=deprecated-declarations' \
      LDFLAGS="-L$P/lib" CPPFLAGS="-I$P/include" PKG_CONFIG_PATH="$PKG_CONFIG_PATH" \
      >"$HERE/evidence/plain-cjose-configure.log" 2>&1
    make -j4 >"$HERE/evidence/plain-cjose-build.log" 2>&1
    make install >>"$HERE/evidence/plain-cjose-build.log" 2>&1
fi

cd "$PLAIN"
if [ ! -f Makefile ]; then
    ./autogen.sh >"$HERE/evidence/plain-module-autogen.log" 2>&1
    ./configure --with-apxs="$APXS" CFLAGS='-O1 -g -fno-omit-frame-pointer' \
      >"$HERE/evidence/plain-module-configure.log" 2>&1
fi
make -j4 >"$HERE/evidence/plain-module-build.log" 2>&1
echo "MODULE: $(sha256sum "$PLAIN/src/.libs/mod_auth_openidc.so")"
