#!/usr/bin/env bash
# Build the released v2.4.19.4 module against the same plain httpd/APR stack
# as build-plain.sh, for the long-token crash control. Loopback lab only.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$HERE/../../apache2shell/build"
P="$HERE/plain-prefix"
SRC="$HERE/src/mod_auth_openidc"
PLAIN="$HERE/src/mod_auth_openidc-plain-fixed"
APXS="$B/httpd-2.4.70-install/bin/apxs"
export PKG_CONFIG_PATH="$P/lib/pkgconfig"
if [ ! -d "$PLAIN" ]; then
    git -C "$SRC" worktree add -q "$PLAIN" v2.4.19.4
fi
echo "PIN: $(sha256sum "$PLAIN/src/state.c")"
cd "$PLAIN"
./autogen.sh >"$HERE/evidence/plain-fixed-module-autogen.log" 2>&1
./configure --with-apxs="$APXS" CFLAGS='-O1 -g -fno-omit-frame-pointer' \
  >"$HERE/evidence/plain-fixed-module-configure.log" 2>&1
make -j4 >"$HERE/evidence/plain-fixed-module-build.log" 2>&1
echo "MODULE: $(sha256sum "$PLAIN/src/.libs/mod_auth_openidc.so")"
