#!/bin/sh
# fontforge2shell W28: two-import indirect-call lane is out of reach.
# First negative-glyph write zeroes Encoding.tounicode (the process survives);
# the second import's encs chunk lands >1 KiB from that Encoding, so its
# negative write cannot set tounicode_func and no indirect call occurs.
# Prerequisites: build-plain and build-nopie. No network or loopback service.
set -u
cd "$(dirname "$0")" || exit 2
[ -x build-nopie/bin/fontforge ] || { echo 'missing build-nopie' >&2; exit 2; }
[ -x build-plain/bin/fontforge ] || { echo 'missing build-plain' >&2; exit 2; }

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }
lacks() { ! grep -qF "$1" "$2"; }

python3 make-funcpath-case.py 0x406ec0 > funcpath-gen.out || exit 2
timeout 30 build-nopie/bin/fontforge -script import-funcpath.ff > funcpath-plain.out 2>&1
plain_rc=$?
check 'plain two-import run survives first descriptor zeroing' test "$plain_rc" -eq 0

gdb -q -batch -x gdb-w28-funcpath-nopie.cmd build-nopie/bin/fontforge \
    > gdb-w28-funcpath-nopie.out 2>&1
check 'first store sees live iconv descriptor' sh -c "! grep -E '^W28S1 .* tounicode=\(nil\)' gdb-w28-funcpath-nopie.out"
check 'first store sees NULL tounicode_func' has 'tounicode_func=(nil)' gdb-w28-funcpath-nopie.out
second=$(grep '^W28S2' gdb-w28-funcpath-nopie.out)
check 'second import zeroes tounicode' python3 -c '
import pathlib, sys
line = next(l for l in pathlib.Path(sys.argv[1]).read_text().splitlines() if l.startswith("W28S2"))
sys.exit(0 if "tounicode=(nil)" in line and "tounicode_func=(nil)" in line else 1)
' gdb-w28-funcpath-nopie.out
check 'no indirect call through tounicode_func' lacks 'W28CALL' gdb-w28-funcpath-nopie.out
check 'second encs is farther than 1 KiB from Encoding' python3 -c '
import re, sys
m = re.search(r"delta=-(\d+)", sys.argv[1])
sys.exit(0 if m and int(m.group(1)) > 1024 else 1)
' "$second"

# Vary the number of benign imports before the second negative write. The
# Encoding pointer stays fixed while encs moves further away in every case.
: > gdb-w28-sweep.out
for n in 0 1 2 3 4 5 6 7 8; do {
    echo 'New()'
    echo "Import(\"$PWD/funczero.pcf\")"
    i=0
    while [ "$i" -lt "$n" ]; do
        echo "Import(\"$PWD/size-complete.pcf\")"
        i=$((i+1))
    done
    echo "Import(\"$PWD/funcptr.pcf\")"
} > /tmp/ff2s-w28-sweep.ff
    echo "n=$n" >> gdb-w28-sweep.out
    timeout 30 gdb -q -batch -x gdb-w28-sweep.cmd build-nopie/bin/fontforge 2>&1 |
        grep '^W28SWEEP' >> gdb-w28-sweep.out
done
check 'nine sweep cases recorded' test "$(grep -c '^n=' gdb-w28-sweep.out)" -eq 9
check 'every sweep case has both stores' test "$(grep -c 'W28SWEEP bp=1 glyph=' gdb-w28-sweep.out)" -eq 18
check 'every second store is out of the 1 KiB reach' python3 -c '
import re, pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
deltas = []
for line in text.splitlines():
    if "glyph=-170" in line:
        m = re.search(r"delta=-(\d+)", line)
        deltas.append(int(m.group(1)) if m else 0)
sys.exit(0 if len(deltas) == 9 and all(d > 1024 for d in deltas) else 1)
' gdb-w28-sweep.out

check 'tounicode_func has a guarded call site' has 'encname->tounicode_func)(enc)' \
    src/fontforge-20251009/fontforge/encoding.c
check 'no assignment site for tounicode_func' sh -c \
    "! grep -REn 'tounicode_func[[:space:]]*=[^=]' src/fontforge-20251009/fontforge --include='*.c'"

echo '=== W28 normalized hashes ==='
for f in funczero.pcf funcptr.pcf gdb-w28-funcpath-nopie.out gdb-w28-sweep.out; do
    printf '%s  ' "$f"
    sha256sum "$f" | cut -d' ' -f1
done
echo "REPLAY_W28_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
