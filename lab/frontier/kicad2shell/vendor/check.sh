#!/bin/sh
# Vendor-produced .SchLib reachability lane for kicad2shell (2026-11-23 W180).
#
# The unmodified fixture is a real Altium schematic library from KiCad's own QA
# data. The patched fixtures each change ONE FileHeader property key in place
# (same byte length, CFB structure untouched). All five go through the
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
    'mounting_holes-sizez7.SchLib':['SIZE1=10', 'SIZEZ=7'],
    'mounting_holes-sizez1.SchLib':['SIZE1=10', 'SIZEZ=1'],
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

for f in mounting_holes mounting_holes-size0 mounting_holes-sizez mounting_holes-sizez7 mounting_holes-sizez1; do
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
# four bytes actually stored before data(). One probe per chosen value.
set +e
for v in 9 7 1; do
    case "$v" in
        9) f=mounting_holes-sizez.SchLib; o=vendor-gdb.out; r=vendor-gdb.rc ;;
        *) f=mounting_holes-sizez$v.SchLib; o=vendor-gdb$v.out; r=vendor-gdb$v.rc ;;
    esac
    gdb -q -batch -ex 'set pagination off' \
        -ex 'break sch_io_altium.cpp.vuln:5919' \
        -ex "run $HERE/$f" -ex 'continue' \
        -ex 'printf "GDBKEY=%s GDBIND=%d GDBSCALED=0x%08x\n", remaining.s.c_str(), ind, scaled' \
        -ex 'next' -ex 'x/4xb (char*)aFontSizes._M_impl._M_start-4' \
        "$READER/g++-vuln-plain" > "evidence/$o" 2>&1
    echo $? > "evidence/$r"
done
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
# Three values patch the same byte 685; the stored word follows file bytes.
for spec in ('mounting_holes-sizez 9 0x00000040 40',
             'mounting_holes-sizez7 7 0x00000032 32',
             'mounting_holes-sizez1 1 0x00000007 07'):
    f, v, scaled, byte = spec.split()
    zp = out(f, "g++-vuln-plain")
    za = out(f, "g++-vuln-asan")
    check(rc(f, "g++-vuln-plain") == 134
          and 'real-key: SIZEZ=' + v in za
          and 'double free or corruption (out)' in zp,
          'vendor-sizez%s vuln-plain rc=134 glibc chunk corruption' % v)
    check(rc(f, "g++-vuln-asan") == 1
          and 'heap-buffer-overflow' in za and 'WRITE of size 4' in za
          and '4 bytes before 4-byte region' in za
          and 'sch_io_altium.cpp.vuln:5919' in za
          and 'sch_io_altium.cpp.vuln:5915' in za,
          'vendor-sizez%s vuln-asan WRITE 4 before 4-byte region at :5919' % v)
    for b in ('g++-fixed-plain', 'g++-fixed-asan'):
        o = out(f, b)
        check(rc(f, b) == 0 and 'rc=0 size=1 first=72 GUARD7=11111111' in o
              and 'AddressSanitizer' not in o,
              'vendor-sizez%s fixed %s rc=0 size=1 intact' % (v, b))
    gname = 'vendor-gdb.out' if v == '9' else 'vendor-gdb%s.out' % v
    g = (e / gname).read_text(errors='replace')
    check('GDBKEY=Z GDBIND=0 GDBSCALED=' + scaled in g
          and '0x%s\t0x00\t0x00\t0x00' % byte in g,
          'vendor-gdb%s ind=0 scaled=%s bytes=%s 00 00 00 at data()-4' % (v, scaled, byte))


text = '\n'.join('PASS ' + line for line in trace) + '\n'
(e / 'trace-vendor.txt').write_text(text)
h = hashlib.sha256(text.encode()).hexdigest()
(e / 'trace-vendor.sha256').write_text(h + '  trace-vendor.txt\n')
print('PASS=%d FAIL=0' % len(trace))
print('TRACE_SHA256=' + h)
PY
