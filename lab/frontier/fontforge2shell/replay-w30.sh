#!/bin/sh
# fontforge2shell W30: symmetric fromunicode lane is a written-but-unused pointer.
# The pinned negative-glyph store overwrites Encoding.fromunicode (encs-688) in
# the real non-PIE build with a chosen mapped .text address. Import() calls
# iconv only through tounicode, and Import()+Save() never reaches EncFromUni,
# so the chosen address is never a call destination. No branch, marker or r5.
# Prerequisites: build-nopie and build-fixed-nopie. No network or loopback.
set -u
cd "$(dirname "$0")" || exit 2
[ -x build-nopie/bin/fontforge ] || { echo 'missing build-nopie' >&2; exit 2; }
[ -x build-fixed-nopie/bin/fontforge ] || { echo 'missing build-fixed-nopie' >&2; exit 2; }

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }
lacks() { ! grep -qF "$1" "$2"; }

python3 make-frompath-case.py > frompath-gen.out || exit 2
check 'generated PCF hash matches committed case' sh -c \
    'test "$(sha256sum frompath.pcf | cut -d" " -f1)" = f4513ca207a8742821ce76a9cc307e065cbc3183fa34e6cd570e277fccdf9a2b'

gdb -q -batch -x gdb-w30-frompath-nopie.cmd build-nopie/bin/fontforge \
    > gdb-w30-frompath-nopie.out 2>&1
check 'store breakpoint sees negative glyph and live descriptor' \
    has 'W30F before glyph=-172 fromunicode=0x' gdb-w30-frompath-nopie.out
check 'chosen value reaches Encoding.fromunicode' \
    has 'W30F after glyph=-172 fromunicode=0x414243' gdb-w30-frompath-nopie.out
check 'no iconv call with chosen descriptor' lacks 'W30F iconv-hit' gdb-w30-frompath-nopie.out
check 'no EncFromUni call after the write' lacks 'W30F EncFromUni-hit' gdb-w30-frompath-nopie.out
check 'gdb process exits normally' has 'W30F exited' gdb-w30-frompath-nopie.out

timeout 30 build-nopie/bin/fontforge -script import-frompath.ff > frompath-import.out 2>&1
check 'plain Import survives' test "$?" -eq 0
timeout 30 build-nopie/bin/fontforge -script import-frompath-save.ff > frompath-save.out 2>&1
check 'plain Import+Save survives' test "$?" -eq 0
timeout 30 build-fixed-nopie/bin/fontforge -script import-frompath-save.ff > frompath-fixed.out 2>&1
check 'patched build survives the same file' test "$?" -eq 0
check 'patched source keeps the glyph guard' has 'glyph>=0 && glyph!=0xffff && glyph<b->glyphcnt' \
    src/fontforge-fixed/fontforge/fvimportbdf.c
check 'fromunicode has a guarded iconv call site' has 'enc->fromunicode,&fpt,&fromlen' \
    src/fontforge-20251009/fontforge/encoding.c
check 'no assignment site for fromunicode_func' sh -c \
    "! grep -REn 'fromunicode_func[[:space:]]*=[^=]' src/fontforge-20251009/fontforge --include='*.c'"

echo '=== W30 normalized hashes ==='
for f in frompath.pcf gdb-w30-frompath-nopie.out; do
    printf '%s  ' "$f"
    sha256sum "$f" | cut -d' ' -f1
done
echo "REPLAY_W30_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
