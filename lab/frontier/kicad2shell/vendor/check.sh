#!/bin/sh
# Vendor-produced .SchLib reachability lane for kicad2shell (2026-11-23 W180).
#
# The unmodified fixture is a real Altium schematic library from KiCad's own QA
# data. The two patched fixtures change ONE FileHeader property key in place
# (same byte length, CFB structure untouched). All three go through the
# already-committed kicadreader binaries: KiCad 10.0.6's own verbatim
# compoundfilereader plus the pinned ALTIUM_BINARY_PARSER and ParseLibHeader.
# No new upstream bytes, no rebuild, no network at check time.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
READER=$(CDPATH= cd -- "$HERE/../kicadreader" && pwd)
mkdir -p "$HERE/evidence"
cd "$HERE"

printf 'vendor-pins: '
sha256sum -c PINS-vendor.sha256

# Independent CFB read-back, including the exact property keys the parser sees.
python3 - > evidence/vendor-olefile.out 2>&1 <<'PY'
import olefile
expect = {
    'mounting_holes.SchLib':      ['SIZE1=10', 'SIZE2=9'],
    'mounting_holes-size0.SchLib':['SIZE0=99', 'SIZE2=9'],
    'mounting_holes-sizez.SchLib':['SIZE1=10', 'SIZEZ=9'],
}
for path, keys in expect.items():
    ok = olefile.isOleFile(path)
    o = olefile.OleFileIO(path)
    streams = o.listdir()
    data = o.openstream('FileHeader').read()
    o.close()
    seen = [b.upper().decode() for b in data.split(b'|') if b.upper().startswith(b'SIZE')]
    assert ok and ['FileHeader'] in streams and seen == keys, (path, ok, streams, seen)
    print('olefile %s valid=%s streams=%d FileHeader=%d keys=%s PASS'
          % (path, ok, len(streams), len(data), ','.join(seen)))
PY
cat evidence/vendor-olefile.out

for f in mounting_holes mounting_holes-size0 mounting_holes-sizez; do
    for b in g++-vuln-plain g++-vuln-asan g++-fixed-plain g++-fixed-asan; do
        set +e
        case "$b" in
            *asan) ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
                       "$READER/$b" "$HERE/$f.SchLib" > "evidence/$f-$b.out" 2>&1 ;;
            *)     "$READER/$b" "$HERE/$f.SchLib" > "evidence/$f-$b.out" 2>&1 ;;
        esac
        echo $? > "evidence/$f-$b.rc"
        set -e
    done
done

# gdb: skip the first :5919 hit (valid SIZE1), then read ind/scaled and the
# four bytes actually stored before data().
set +e
gdb -q -batch -ex 'set pagination off' \
    -ex 'break sch_io_altium.cpp.vuln:5919' \
    -ex "run $HERE/mounting_holes-sizez.SchLib" -ex 'continue' \
    -ex 'printf "GDBKEY=%s GDBIND=%d GDBSCALED=0x%08x\n", remaining.s.c_str(), ind, scaled' \
    -ex 'next' -ex 'x/4xb (char*)aFontSizes._M_impl._M_start-4' \
    "$READER/g++-vuln-plain" > evidence/vendor-gdb.out 2>&1
echo $? > evidence/vendor-gdb.rc
set -e

python3 - <<'PY'
import hashlib, pathlib
e = pathlib.Path('evidence')

def out(f, b):
    return (e / (f + '-' + b + '.out')).read_text(errors='replace')

def rc(f, b):
    return int((e / (f + '-' + b + '.rc')).read_text().strip())

trace = []
def check(cond, msg):
    assert cond, 'ASSERT FAILED: ' + msg
    trace.append(msg)

# Unmodified vendor file: both builds parse the real mixed-case Size1/Size2
# keys (uppercased by the verbatim ReadProperties) without any fault.
for b in ('g++-vuln-plain', 'g++-vuln-asan', 'g++-fixed-plain', 'g++-fixed-asan'):
    o = out('mounting_holes', b)
    check(rc('mounting_holes', b) == 0 and 'stream=551' in o
          and 'parse_error=0' in o and 'real-key: SIZE1=10' in o
          and 'real-key: SIZE2=9' in o
          and 'rc=0 size=2 first=72 GUARD7=11111111' in o
          and 'AddressSanitizer' not in o,
          'vendor-unmodified %s rc=0 size=2 no-ASan' % b)

# Hostile key sorting BEFORE the valid one: empty vector, null-adjacent store.
# Preserved as a distinct observed fault mode, not a separate vulnerability.
o0p, o0a = out('mounting_holes-size0', 'g++-vuln-plain'), out('mounting_holes-size0', 'g++-vuln-asan')
check(rc('mounting_holes-size0', 'g++-vuln-plain') == 139
      and 'real-key: SIZE0=99' in o0p and 'rc=0 size=' not in o0p,
      'vendor-size0 vuln-plain rc=139 null-adjacent store')
check(rc('mounting_holes-size0', 'g++-vuln-asan') == 1
      and 'AddressSanitizer: SEGV' in o0a and 'sch_io_altium.cpp.vuln:5919' in o0a,
      'vendor-size0 vuln-asan SEGV at pinned :5919')
for b in ('g++-fixed-plain', 'g++-fixed-asan'):
    o = out('mounting_holes-size0', b)
    check(rc('mounting_holes-size0', b) == 0 and 'rc=0 size=2 first=0 GUARD7=11111111' in o
          and 'AddressSanitizer' not in o, 'vendor-size0 fixed %s rc=0 size=2 intact' % b)

# Hostile key sorting AFTER the valid one: the vector is allocated first, so
# the same real-file patch reproduces the pinned four-byte heap underflow.
ozp, oza = out('mounting_holes-sizez', 'g++-vuln-plain'), out('mounting_holes-sizez', 'g++-vuln-asan')
check(rc('mounting_holes-sizez', 'g++-vuln-plain') == 134
      and 'real-key: SIZEZ=9' in oza and 'double free or corruption (out)' in ozp,
      'vendor-sizez vuln-plain rc=134 glibc chunk corruption')
check(rc('mounting_holes-sizez', 'g++-vuln-asan') == 1
      and 'heap-buffer-overflow' in oza and 'WRITE of size 4' in oza
      and '4 bytes before 4-byte region' in oza
      and 'sch_io_altium.cpp.vuln:5919' in oza
      and 'sch_io_altium.cpp.vuln:5915' in oza,
      'vendor-sizez vuln-asan WRITE 4 before 4-byte region at :5919')
for b in ('g++-fixed-plain', 'g++-fixed-asan'):
    o = out('mounting_holes-sizez', b)
    check(rc('mounting_holes-sizez', b) == 0 and 'rc=0 size=1 first=72 GUARD7=11111111' in o
          and 'AddressSanitizer' not in o, 'vendor-sizez fixed %s rc=0 size=1 intact' % b)

g = (e / 'vendor-gdb.out').read_text(errors='replace')
check('GDBKEY=Z GDBIND=0 GDBSCALED=0x00000040' in g
      and '0x40\t0x00\t0x00\t0x00' in g,
      'vendor-gdb ind=0 scaled=0x40 bytes=40 00 00 00 at data()-4')

text = '\n'.join('PASS ' + line for line in trace) + '\n'
(e / 'trace-vendor.txt').write_text(text)
h = hashlib.sha256(text.encode()).hexdigest()
(e / 'trace-vendor.sha256').write_text(h + '  trace-vendor.txt\n')
print('PASS=%d FAIL=0' % len(trace))
print('TRACE_SHA256=' + h)
PY
