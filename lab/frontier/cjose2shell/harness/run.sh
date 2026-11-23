#!/bin/sh
# cjose2shell direct-call harness build.
# Upstream bytes: pinned cjose v0.6.2.4 trees + the single fix hunk from
# commit 8c51d245. Real cjose_jwe_import()/cjose_jwe_decrypt() and real OpenSSL
# AES_unwrap_key; internal header included only for lab inspection of cek.
# No socket, server, application, wire listener, pointer control or command.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
JANSSON="$ROOT/deps/jansson-prefix"
mkdir -p "$HERE/evidence"
(cd "$ROOT" && sha256sum -c PINS.sha256 >/dev/null)

for tree in vulnerable fixed; do
    for cc in gcc clang; do
        for mode in asan plain; do
            if [ "$mode" = asan ]; then
                FLAGS='-fsanitize=address'
                if [ "$cc" = clang ]; then SRC="$ROOT/src/clang-$tree"; else SRC="$ROOT/src/$tree"; fi
            else
                FLAGS=''
                SRC="$ROOT/src/plain-$cc-$tree"
            fi
            [ -f "$SRC/src/.libs/libcjose.a" ] || { echo "missing lib for $cc/$tree/$mode" >&2; exit 1; }

            $cc -g -O0 -fno-omit-frame-pointer -Wall $FLAGS \
                -I"$SRC/include" -I"$SRC/src" -I"$JANSSON/include" \
                "$HERE/driver.c" "$SRC/src/.libs/libcjose.a" \
                "$JANSSON/lib/libjansson.a" -lcrypto -lm \
                -o "$HERE/$cc-$tree-$mode"
        done
    done
done
printf 'built 8 binaries; pins verified\n'
