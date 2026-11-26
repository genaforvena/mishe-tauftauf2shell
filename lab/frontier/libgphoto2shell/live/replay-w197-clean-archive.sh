#!/bin/sh
# W199: one-command, clean-archive replay of W197's device-only top-header
# lane. Run from a clean git archive (or the repository root):
#
#   git archive HEAD reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell \
#     | tar x -C /tmp/w199-clean
#   cd /tmp/w199-clean
#   TARBALL=/path/to/libgphoto2-2.5.34.tar.bz2 \
#     sh lab/frontier/libgphoto2shell/live/replay-w197-clean-archive.sh
#
# The release tarball is provisioned, not committed; TARBALL defaults to the
# author's pinned copy. WORK defaults to /tmp/w199-lgp-replay and is recreated
# on each run. The script applies the exact six-patch lab chain, builds GCC
# -O2 from scratch, derives the top-chunk size from its own gdb map, then runs
# the unchanged W197 replay/checker. No /tmp author build is reused.
# Author replay, NOT a witness verdict. LAB ONLY: no wire, physical USB,
# command, or rung 5.
set -eu

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
T=$(CDPATH= cd -- "$HERE/.." && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../../.." && pwd)
TARBALL=${TARBALL:-$T/src/libgphoto2-2.5.34.tar.bz2}
WORK=${WORK:-/tmp/w199-lgp-replay}
TAR_SHA=5df9e774eb4ab6087a193afff84dcafe9f666e3443fe29e73e6779f659ff7f28
VULN_SHA=0ccb1dac24a837bc58a414942cc74bec47586b826c6c0c91ddcec3adea3d6185

[ -f "$TARBALL" ] || { echo "missing TARBALL=$TARBALL" >&2; exit 2; }
got=$(sha256sum "$TARBALL" | cut -d' ' -f1)
[ "$got" = "$TAR_SHA" ] || { echo "tarball sha256 $got != $TAR_SHA" >&2; exit 2; }
for tool in gdb setarch gcc patch pkg-config python3; do
	command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 2; }
done

echo "== pins =="
(cd "$ROOT" && sha256sum -c lab/frontier/libgphoto2shell/PINS.sha256)

echo "== clean source and lab patch chain =="
rm -rf "$WORK"
mkdir -p "$WORK/src" "$WORK/build"
tar xjf "$TARBALL" -C "$WORK/src"
S=$WORK/src/libgphoto2-2.5.34
cd "$S"
patch -p1 < "$T/live/vusb-jl2005.patch" > "$WORK/patch-1.log"
patch -p1 < "$T/evidence/replay-vusb-local-modes.patch" > "$WORK/patch-2.log"
patch -p1 < "$T/evidence/replay-vusb-ret.patch" > "$WORK/patch-3.log"
patch -p1 < "$T/evidence/replay-vusb-partial-priv.patch" > "$WORK/patch-4.log"
patch -p1 < "$T/evidence/replay-vusb-heap-header-repair.patch" > "$WORK/patch-5.log"
patch -p1 < "$T/evidence/w195-vusb-natural-repair.patch" > "$WORK/patch-6.log"
got=$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)
[ "$got" = "$VULN_SHA" ] || { echo "vulnerable source sha256 $got != $VULN_SHA" >&2; exit 2; }
grep -q M2SHELL_W195_PRIV "$S/libgphoto2_port/vusb/vusb.c" || {
	echo "W195 repair patch missing" >&2; exit 2; }
echo "vulnerable jl2005c.c sha256 $got OK"

echo "== fresh GCC -O2 build =="
B=$WORK/build
P=$B/installdir
cd "$B"
"$S/configure" --prefix="$P" --with-camlibs=jl2005c --enable-shared \
	--disable-static --without-libxml-2.0 --without-libcurl \
	--without-gdlib --without-libtiff-4 --without-libexif \
	--disable-nls --enable-vusb \
	CFLAGS='-O2 -g -fPIC -fno-omit-frame-pointer -fno-stack-protector' \
	> "$WORK/configure.log" 2>&1
make -j4 > "$WORK/make.log" 2>&1
make install > "$WORK/install.log" 2>&1
[ -f "$P/lib/libgphoto2/2.5.34/jl2005c.so" ] || { echo "camlib not installed" >&2; exit 2; }
echo "jl2005c.so sha256 $(sha256sum "$P/lib/libgphoto2/2.5.34/jl2005c.so" | cut -d' ' -f1)"

echo "== probe and fresh top-size derivation =="
PROBE=$B/consumer-probe
gcc -O2 -g -fno-omit-frame-pointer -I"$P/include" -I"$T/pins" \
	$(pkg-config --cflags glib-2.0) \
	"$T/evidence/replay-file-consumer-probe.c" -o "$PROBE" \
	-L"$P/lib" -lgphoto2 -lgphoto2_port $(pkg-config --libs glib-2.0)
COMMON="CAMLIBS=$P/lib/libgphoto2/2.5.34 IOLIBS=$P/lib/libgphoto2_port/0.12.2 IOLIBS_PREFIX=vusb LD_LIBRARY_PATH=$P/lib"
# shellcheck disable=SC2086
timeout 30 gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
	-ex 'set breakpoint pending on' -ex 'set disable-randomization on' \
	-ex 'break jl2005c.c:155' -ex run -ex 'x/2gx (char*)priv+0x4040' \
	-ex kill --args env $COMMON M2SHELL_JL2005_VUSB=s \
	M2SHELL_JL2005_COUNT=100 "$PROBE" usb:001,001 "$WORK/preflight.bin" \
	> "$WORK/preflight-gdb.out" 2>&1
TOP=$(python3 - "$WORK/preflight-gdb.out" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
words = re.findall(r'0x[0-9a-f]{16}', text)
if len(words) < 2:
    raise SystemExit("top-size derivation failed; see preflight-gdb.out")
print(words[-1])
PY
)
echo "fresh TOP=$TOP (build constant, not device observable)"

echo "== unchanged W197 replay and checker =="
S="$S" B="$B" TOP="$TOP" OUT="$WORK/w197.out" \
	sh "$T/live/replay-w197-gcc-o2-device-only.sh" || rc=$?
rc=${rc:-0}
tail -n 20 "$WORK/w197.out"
echo "WRAPPER RESULT rc=$rc TOP=$TOP OUT=$WORK/w197.out"
exit "$rc"
