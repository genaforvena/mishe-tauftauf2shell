#!/bin/bash
# Isolated build: PIC cjose v0.6.2.4 + real mod_auth_openidc 2.4.15.1.
set -euo pipefail
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
JANSSON="$ROOT/deps/jansson-prefix"
MODSRC="$ROOT/src/provisioning/mod_auth_openidc-2.4.15.1"
mkdir -p "$HERE/evidence" "$HERE/pkgconfig"

cat > "$HERE/pkgconfig/jansson.pc" <<EOF
prefix=$JANSSON
libdir=\${prefix}/lib
includedir=\${prefix}/include
Name: jansson
Description: Jansson JSON library (local harness prefix)
Version: 2.14
Libs: -L\${libdir} -ljansson
Cflags: -I\${includedir}
EOF

cat > "$HERE/pkgconfig/cjose.pc" <<EOF
prefix=$HERE/cjose-vuln
libdir=\${prefix}/src/.libs
includedir=\${prefix}/include
Name: cjose
Description: pinned vulnerable cjose v0.6.2.4, PIC static build
Version: 0.6.2.4
Libs: -L\${libdir} -lcjose -L$JANSSON/lib -ljansson -lcrypto -lm
Cflags: -I\${includedir} -I$JANSSON/include
EOF

build_cjose() {
    local dir=$1
    if [ ! -d "$dir" ]; then cp -a "$ROOT/src/vulnerable" "$dir"; fi
    ( cd "$dir" && make distclean >/dev/null 2>&1 || true
      CC=gcc ./configure --with-jansson="$JANSSON" --disable-shared --enable-static \
        CFLAGS='-g -O0 -fPIC -fno-omit-frame-pointer' > configure.log 2>&1
      make -j4 > build.log 2>&1 )
    echo "CJOSE_BUILT=$dir"
}

build_cjose "$HERE/cjose-vuln"

if [ ! -d "$HERE/mod_auth_openidc" ]; then cp -a "$MODSRC" "$HERE/mod_auth_openidc"; fi
( cd "$HERE/mod_auth_openidc"
  ./autogen.sh > autogen.log 2>&1
  PKG_CONFIG_PATH="$HERE/pkgconfig" ./configure --with-apxs=/usr/bin/apxs \
    CFLAGS='-g -O0 -fPIC -fno-omit-frame-pointer' > configure.log 2>&1
  make -j4 > build.log 2>&1 )
echo "MODULE_BUILT=$HERE/mod_auth_openidc/.libs/mod_auth_openidc.so"
