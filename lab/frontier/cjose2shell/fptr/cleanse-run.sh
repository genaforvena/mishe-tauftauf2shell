#!/bin/sh
# W196: measure CEK bytes at free() entry, vulnerable and fixed plain builds.
# Real pinned cjose libraries; no listener, credential or shell command.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
JANSSON="$ROOT/deps/jansson-prefix"
mkdir -p "$HERE/evidence"
(cd "$ROOT" && sha256sum -c PINS.sha256 >/dev/null)

for tree in vulnerable fixed; do
    SRC="$ROOT/src/plain-gcc-$tree"
    [ -f "$SRC/src/.libs/libcjose.a" ] || { echo "missing lib for $tree" >&2; exit 1; }
    gcc -g -O0 -fno-omit-frame-pointer -Wall -Wl,--wrap=free \
        -I"$SRC/include" -I"$SRC/src" -I"$JANSSON/include" \
        "$HERE/cleanse.c" "$SRC/src/.libs/libcjose.a" \
        "$JANSSON/lib/libjansson.a" -lcrypto -lm \
        -o "$HERE/gcc-$tree-cleanse"
done

for tree in vulnerable fixed; do
    for scenario in attack safe; do
        set +e
        "$HERE/gcc-$tree-cleanse" "$scenario" > "$HERE/evidence/cleanse-$tree-$scenario.out" 2>&1
        rc=$?
        set -e
        printf '%s %s rc=%d\n' "$tree" "$scenario" "$rc"
        cat "$HERE/evidence/cleanse-$tree-$scenario.out"
    done
done
