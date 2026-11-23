#!/usr/bin/env bash
# Identify the natural out-of-bounds NUL store target in a real APR pool.
# The plain verbatim-slice binary is used because the ASan build faults on the
# read at pinned state.c:214 before the store at :219.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/evidence/oob-target"
mkdir -p "$OUT"
for fill in 0 512 1024 2048 4000 8000; do
    gdb -q -batch \
        -ex 'set pagination off' \
        -ex 'break state.c.4301b536:219' \
        -ex "run read $fill" \
        -ex 'printf "FILL='"$fill"' TOKEN=%p STORE=%p DELTA=%ld PTR_BEFORE=%p STR_BEFORE=%s\n", cookieName, cookie, (long)(cookie-cookieName), *(void**)cookie, *(char**)cookie' \
        -ex 'next' \
        -ex 'printf "FILL='"$fill"' PTR_AFTER=%p STR_AFTER=%s\n", *(void**)cookie, *(char**)cookie' \
        "$HERE/p-vuln" >"$OUT/fill-$fill.txt" 2>&1
done
cat "$OUT"/fill-*.txt
