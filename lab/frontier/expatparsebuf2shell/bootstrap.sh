#!/bin/bash
# expatparsebuf2shell: rebuild every pinned tree and harness from pins/.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
cd "$D"

rm -rf vuln patched fixed expat-2.8.5 expat-2.9.0
tar xzf pins/vuln.tar.gz
mv expat-2.8.5 vuln
tar xzf pins/fixed.tar.gz
mv expat-2.9.0 fixed
cp -a vuln patched
(cd patched && patch -p2 --silent < ../pins/fix.patch)

CC=${CC:-gcc}
ASAN="-g -O1 -fsanitize=address -fno-omit-frame-pointer"
PLAIN="-g -O2"

build() {
    local out="$1" src="$2" harness="$3" flags="$4" extra="$5"
    # shellcheck disable=SC2086
    $CC $flags -I "$src" -I "$src/lib" "$harness" \
        "$src/lib/xmlparse.c" "$src/lib/xmltok.c" "$src/lib/xmlrole.c" \
        $extra -o "$out"
}

VULN_EXTRA="vuln/lib/random_arc4random_buf.c"
PATCHED_EXTRA="patched/lib/random_arc4random_buf.c"
FIXED_EXTRA="fixed/lib/random_arc4random_buf.c fixed/lib/xcs.c"

build harness-vuln-asan vuln harness.c "$ASAN" "$VULN_EXTRA"
build harness-patched-asan patched harness.c "$ASAN" "$PATCHED_EXTRA"
build harness-fixed-asan fixed harness.c "$ASAN" "$FIXED_EXTRA"
build harness-vuln-plain vuln harness.c "$PLAIN" "$VULN_EXTRA"
build harness-vuln-arena-plain vuln harness-arena.c "$PLAIN" "$VULN_EXTRA"
build harness-patched-arena-plain patched harness-arena.c "$PLAIN" "$PATCHED_EXTRA"
build harness-fixed-arena-plain fixed harness-arena.c "$PLAIN" "$FIXED_EXTRA"

echo "BOOTSTRAP_OK: $(date -u +%FT%TZ)"
