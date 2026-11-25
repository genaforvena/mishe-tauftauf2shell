#!/bin/sh
# fontforge2shell W29: one truncated BDF_ENCODINGS table can perform two
# negative-glyph stores, but the second is forced to encs[-4] with a nonzero
# value, so it corrupts the malloc chunk size and aborts. No second
# independently chosen offset, no survivable multi-write primitive.
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

python3 make-twostore-case.py > twostore-gen.out || exit 2
check 'crafted PCF keeps one trailing index byte' test "$(stat -c %s twostore.pcf)" -eq 291

for b in nopie plain; do
    timeout 60 gdb -q -batch -x gdb-w29-twostore.cmd build-$b/bin/fontforge \
        > gdb-w29-twostore-$b.out 2>&1
    s1=$(grep '^W29S1' gdb-w29-twostore-$b.out)
    s2=$(grep '^W29S2' gdb-w29-twostore-$b.out)
    check "$b first store glyph=-2 i=0 value=0" python3 -c '
import sys
s = sys.argv[1]
sys.exit(0 if "i=0 glyph=-2" in s and "value=0 " in s else 1)
' "$s1"
    check "$b second store glyph=-1 i=1 value=1" python3 -c '
import sys
s = sys.argv[1]
sys.exit(0 if "i=1 glyph=-1" in s and "value=1 " in s else 1)
' "$s2"
    check "$b both stores share one encs allocation" python3 -c '
import re, sys
p = [re.search(r"encs=(0x[0-9a-f]+)", s) for s in sys.argv[1:]]
sys.exit(0 if p[0] and p[1] and p[0].group(1) == p[1].group(1) else 1)
' "$s1" "$s2"
    post=$(grep '^W29POST' gdb-w29-twostore-$b.out)
    check "$b second store poisons chunk size high dword" python3 -c '
import re, sys
m = re.search(r"word\[-4\]=(0x[0-9a-f]+)", sys.argv[1])
sys.exit(0 if m and int(m.group(1), 16) > 0 else 1)
' "$post"
    check "$b abort follows the two stores" has 'Program received signal SIGABRT' gdb-w29-twostore-$b.out
done

timeout 30 build-nopie/bin/fontforge -script import-twostore.ff > twostore-plain.out 2>&1
plain_rc=$?
check 'plain non-PIE run aborts (134)' test "$plain_rc" -eq 134
lacks_rc=0
grep -q 'W29S3' gdb-w29-twostore-nopie.out && lacks_rc=1
check 'no third negative store (tot=2)' test "$lacks_rc" -eq 0

# Structural closure: pcfSeekToType stops at the first table of a type, and
# after EOF getformint16 returns -1 for every remaining iteration. The second
# value is V0+1 (divisor>1) or V0+256 (divisor==1), never independently chosen.
check 'TOC lookup takes only the first matching table' sh -c \
    "grep -qF 'for ( i=0; toc[i].type!=0 && toc[i].type!=type; ++i );' src/fontforge-20251009/fontforge/fvimportbdf.c"
check 'parser has no EOF check on glyph indices' sh -c \
    "grep -qF 'glyph = getformint16(file,format);' src/fontforge-20251009/fontforge/fvimportbdf.c &&
     ! grep -qE 'glyph[[:space:]]*==[[:space:]]*EOF|feof[[:space:]]*\(' src/fontforge-20251009/fontforge/fvimportbdf.c"
check 'second value is dependent on the first' python3 -c '
import sys
vals = [((1//d + m2)*256 + (1%d + m1)) - ((0//d + m2)*256 + (0%d + m1))
        for d in (1, 2, 7) for m1 in (0, 3, 200) for m2 in (0, 2, 100)]
sys.exit(0 if vals and set(vals) <= {1, 256} else 1)
'

echo '=== W29 normalized hashes ==='
for f in twostore.pcf gdb-w29-twostore-nopie.out gdb-w29-twostore-plain.out; do
    printf '%s  ' "$f"
    sha256sum "$f" | cut -d' ' -f1
done
printf '%s  ' 'W29 normalized gdb lines'
grep -hE '^W29S' gdb-w29-twostore-nopie.out gdb-w29-twostore-plain.out | sha256sum | cut -d' ' -f1
echo "REPLAY_W29_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
