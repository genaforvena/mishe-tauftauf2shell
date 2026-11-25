#!/bin/sh
# fontforge2shell W25: late-allocation-state scan in both real headless builds.
# The truncated Import() corrupts encs[-1]; this stops at the vulnerable store,
# records encs, continues, and dumps the same 128 KiB window at the abort that
# follows the free. It asserts the later Save() breakpoint is never reached,
# so no later-created object can occupy that window for this trigger.
# Prerequisites: build-plain (replay-real.sh) and build-nopie (replay-nonpie.sh).
# No network, no loopback service, no external probe.
set -u
cd "$(dirname "$0")" || exit 2
[ -x build-plain/bin/fontforge ] || { echo 'missing build-plain' >&2; exit 2; }
[ -x build-nopie/bin/fontforge ] || { echo 'missing build-nopie' >&2; exit 2; }

for lane in pie nopie; do
    case "$lane" in
        pie) bin=build-plain/bin/fontforge ;;
        nopie) bin=build-nopie/bin/fontforge ;;
    esac
    printf 'New()\nImport("%s/truncated.pcf")\nSave("/tmp/ff2s-w25-late-%s.sfd")\n' "$PWD" "$lane" > w25-late.ff
    printf 'set pagination off\nbreak fvimportbdf.c:1751 if glyph < 0\nrun -script %s/w25-late.ff\nprintf "W25 encs=%%p glyph=%%d i=%%d\\n", encs, glyph, i\nset $w25e = encs\nbreak sfd.c:1671\ncontinue\nprintf "W25 late pc=%%p\\n", $pc\ndump binary memory /tmp/ff2s-w25-late-%s.bin (char*)$w25e-131072 (char*)$w25e\ninfo proc mappings\nquit\n' "$PWD" "$lane" > "gdb-w25-$lane.cmd"
    gdb -q -batch -x "gdb-w25-$lane.cmd" "$bin" > "gdb-w25-$lane.out" 2>&1
    python3 scan-w15.py "/tmp/ff2s-w25-late-$lane.bin" "gdb-w25-$lane.out" "$bin" > "scan-w25-$lane.out"
done

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }
lacks() { ! grep -qF "$1" "$2"; }
for lane in pie nopie; do
    check "$lane negative-glyph store reached" has 'glyph=-1 i=3' "gdb-w25-$lane.out"
    check "$lane aborts at the corrupted free" has 'double free or corruption (out)' "gdb-w25-$lane.out"
    check "$lane never reaches the later Save() breakpoint" lacks 'Breakpoint 2,' "gdb-w25-$lane.out"
    check "$lane window has no code-pointer candidate" lacks 'RESULT CODE_POINTER_CANDIDATES' "scan-w25-$lane.out"
done

echo '=== W25 hashes ==='
sha256sum scan-w25-pie.out scan-w25-nopie.out gdb-w25-pie.out gdb-w25-nopie.out
echo "REPLAY_W25_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
