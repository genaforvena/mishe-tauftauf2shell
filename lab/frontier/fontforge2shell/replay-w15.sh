#!/bin/sh
# fontforge2shell W15: no live code pointer in the negative-glyph write window.
# Prerequisite: build-plain and build-nopie already built by replay-real.sh
# and replay-nonpie.sh. Offline; no loopback service, no external probe.
set -u
cd "$(dirname "$0")" || exit 2
[ -x build-plain/bin/fontforge ] || { echo 'missing build-plain; run replay-real.sh first' >&2; exit 2; }
[ -x build-nopie/bin/fontforge ] || { echo 'missing build-nopie; run replay-nonpie.sh first' >&2; exit 2; }

printf 'New()\nImport("%s/truncated.pcf")\n' "$PWD" > w15-import.ff
for mode in nopie pie; do
    if [ "$mode" = nopie ]; then bin=build-nopie/bin/fontforge; else bin=build-plain/bin/fontforge; fi
    printf 'set pagination off\nbreak fvimportbdf.c:1751 if glyph < 0\nrun -script w15-import.ff\nprintf "W15 encs=%%p glyph=%%d i=%%d\\n", encs, glyph, i\ndump binary memory /tmp/ff2s-w15-%s.bin (char*)encs-131072 (char*)encs\ninfo proc mappings\nquit\n' \
        "$mode" > "gdb-w15-$mode.cmd"
    gdb -q -batch -x "gdb-w15-$mode.cmd" "./$bin" > "gdb-w15-$mode.out" 2>&1
done
python3 scan-w15.py /tmp/ff2s-w15-nopie.bin gdb-w15-nopie.out build-nopie/bin/fontforge > scan-w15-nopie.out
python3 scan-w15.py /tmp/ff2s-w15-pie.bin gdb-w15-pie.out build-plain/bin/fontforge > scan-w15-pie.out

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }
check 'nopie breakpoint reached with negative glyph' has 'W15 encs=' gdb-w15-nopie.out
check 'pie breakpoint reached with negative glyph' has 'W15 encs=' gdb-w15-pie.out
check 'nopie window has no code-pointer candidates' has 'RESULT ASCII_ONLY' scan-w15-nopie.out
check 'nopie candidate count stable (six ASCII fragments)' has 'CAND_COUNT 6' scan-w15-nopie.out
check 'pie window has no candidates at all' has 'RESULT NONE' scan-w15-pie.out
check 'pie candidate count zero' has 'CAND_COUNT 0' scan-w15-pie.out

echo '=== W15 pins ==='
sha256sum /tmp/ff2s-w15-nopie.bin /tmp/ff2s-w15-pie.bin scan-w15-nopie.out scan-w15-pie.out
echo "REPLAY_W15_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
