#!/bin/sh
# W188 pointer-control lane. Plain builds only (ASan stops at first OOB store).
# Real pinned cjose v0.6.2.4 and v0.6.2.4+fix; real cjose_jwe_import/decrypt and
# real OpenSSL RFC 3394 wrap/unwrap. No listener, credential or shell command.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
JANSSON="$ROOT/deps/jansson-prefix"
mkdir -p "$HERE/evidence"
(cd "$ROOT" && sha256sum -c PINS.sha256 >/dev/null)

for tree in vulnerable fixed; do
    SRC="$ROOT/src/plain-gcc-$tree"
    [ -f "$SRC/src/.libs/libcjose.a" ] || { echo "missing lib for $tree" >&2; exit 1; }
    gcc -g -O0 -fno-omit-frame-pointer -Wall \
        -I"$SRC/include" -I"$SRC/src" -I"$JANSSON/include" \
        "$HERE/driver.c" "$SRC/src/.libs/libcjose.a" \
        "$JANSSON/lib/libjansson.a" -lcrypto -lm \
        -o "$HERE/gcc-$tree-plain"
done

for tree in vulnerable fixed; do
    for scenario in fptr fptrsafe; do
        set +e
        "$HERE/gcc-$tree-plain" "$scenario" > "$HERE/evidence/$tree-$scenario.out" 2>&1
        rc=$?
        set -e
        printf '%s %s rc=%d\n' "$tree" "$scenario" "$rc"
        cat "$HERE/evidence/$tree-$scenario.out"
    done
done
