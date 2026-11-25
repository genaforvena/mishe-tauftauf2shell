#!/bin/sh
# fontforge2shell W24: third build (RelWithDebInfo, -O2 + debug info, PIE).
# W15/W18/W23 code-pointer sweeps left "a third build" UNKNOWN. This script
# performs the same negative-glyph window scan on that third build.
# Prerequisite: build-rel built offline by the W24 cmake command.
# No network, no loopback service, no external probe.
set -u
cd "$(dirname "$0")" || exit 2
[ -x build-rel/bin/fontforge ] || { echo 'missing build-rel; build it first' >&2; exit 2; }

printf 'New()\nImport("%s/truncated.pcf")\n' "$PWD" > w24-import.ff
printf 'set pagination off\nbreak fvimportbdf.c:1751 if glyph < 0\nrun -script w24-import.ff\nprintf "W24 encs=%%p glyph=%%d i=%%d\\n", encs, glyph, i\ndump binary memory /tmp/ff2s-w24-rel.bin (char*)encs-131072 (char*)encs\ninfo proc mappings\nquit\n' > gdb-w24-rel.cmd
gdb -q -batch -x gdb-w24-rel.cmd ./build-rel/bin/fontforge > gdb-w24-rel.out 2>&1
python3 scan-w15.py /tmp/ff2s-w24-rel.bin gdb-w24-rel.out build-rel/bin/fontforge > scan-w24-rel.out

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }
check 'rel breakpoint reached with negative glyph' has 'W24 encs=' gdb-w24-rel.out
check 'rel window has no real code-pointer candidates' has 'RESULT NONE' scan-w24-rel.out
check 'rel candidate count zero' has 'CAND_COUNT 0' scan-w24-rel.out

echo '=== W24 hashes ==='
sha256sum /tmp/ff2s-w24-rel.bin scan-w24-rel.out gdb-w24-rel.out
echo "REPLAY_W24_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
