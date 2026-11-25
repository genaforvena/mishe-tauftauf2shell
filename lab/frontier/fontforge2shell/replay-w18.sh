#!/bin/sh
# fontforge2shell W18: changed-allocation-state sweep for a live code pointer.
# A complete-table import before the truncated one moves `encs` in both real
# headless builds; scan the same full negative-glyph window again.
# Prerequisites: replay-real.sh, replay-nonpie.sh and replay-w15.sh have run
# in this tree (builds and the W15 baseline transcripts exist).
# Offline; no loopback service, no external probe.
set -u
cd "$(dirname "$0")" || exit 2
for f in build-plain/bin/fontforge build-nopie/bin/fontforge \
         gdb-w15-pie.out gdb-w15-nopie.out; do
    [ -f "$f" ] || { echo "missing $f; run replay-real.sh, replay-nonpie.sh and replay-w15.sh first" >&2; exit 2; }
done

printf 'New()\nImport("%s/complete.pcf")\nImport("%s/truncated.pcf")\n' \
    "$PWD" "$PWD" > w18-import.ff
for mode in nopie pie; do
    if [ "$mode" = nopie ]; then bin=build-nopie/bin/fontforge; else bin=build-plain/bin/fontforge; fi
    printf 'set pagination off\nbreak fvimportbdf.c:1751 if glyph < 0\nrun -script w18-import.ff\nprintf "W18 encs=%%p glyph=%%d i=%%d\\n", encs, glyph, i\ndump binary memory /tmp/ff2s-w18-%s.bin (char*)encs-131072 (char*)encs\ninfo proc mappings\nquit\n' \
        "$mode" > "gdb-w18-$mode.cmd"
    gdb -q -batch -x "gdb-w18-$mode.cmd" "./$bin" > "gdb-w18-$mode.out" 2>&1
done
python3 scan-w15.py /tmp/ff2s-w18-nopie.bin gdb-w18-nopie.out build-nopie/bin/fontforge > scan-w18-nopie.out
python3 scan-w15.py /tmp/ff2s-w18-pie.bin gdb-w18-pie.out build-plain/bin/fontforge > scan-w18-pie.out
python3 check-w18-alloc.py > alloc-w18.out

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }
check 'nopie breakpoint reached with negative glyph' has 'W18 encs=' gdb-w18-nopie.out
check 'pie breakpoint reached with negative glyph' has 'W18 encs=' gdb-w18-pie.out
check 'prior import moved encs in both builds' has 'ALLOC_STATE_OK yes' alloc-w18.out
check 'pie window has no candidates at all' has 'RESULT NONE' scan-w18-pie.out
check 'pie candidate count zero' has 'CAND_COUNT 0' scan-w18-pie.out
check 'nopie window has no code-pointer candidates' has 'RESULT ASCII_ONLY' scan-w18-nopie.out
check 'nopie candidate count bounded (path-sensitive)' grep -qE 'CAND_COUNT [0-8]$' scan-w18-nopie.out

echo '=== W18 pins ==='
sha256sum /tmp/ff2s-w18-nopie.bin /tmp/ff2s-w18-pie.bin scan-w18-nopie.out scan-w18-pie.out alloc-w18.out
echo "REPLAY_W18_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
