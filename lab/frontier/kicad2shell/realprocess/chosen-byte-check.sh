#!/bin/sh
# W183: verify the committed real-process chosen-byte evidence without re-running
# the GUI. The logs were produced by provisioned/gui-import.sh <tag> <file> gdb
# against native KiCad 8.0.8; this only re-checks pins and the observed words.
# It does NOT re-prove the crash: see PROVENANCE-native-process.md for the
# environment, the safe-input control and the honest ceiling.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
printf 'w183-pins: '
( cd fixtures && sha256sum -c PINS-w183.sha256 )

python3 - <<'PY'
import hashlib, pathlib

E = pathlib.Path('evidence')
# vendor fixtures live one directory up; their pins are in vendor/PINS-vendor.sha256
V = pathlib.Path('../vendor')
cases = [
    # (tag, SizeZ value in file, fixture basename)
    ('w183-sizez-gdb',        9, 'mounting_holes-sizez.SchLib'),
    ('w183-sizez7-gdb',       7, 'mounting_holes-sizez7.SchLib'),
    ('w183-sizez1-gdb',       1, 'mounting_holes-sizez1.SchLib'),
    ('w183-sizez-138889-gdb', 138889, 'w183-sizez-138889.SchLib'),
    ('w183-sizez-200000-gdb', 200000, 'w183-sizez-200000.SchLib'),
]
pins = {}
for line in (V / 'PINS-vendor.sha256').read_text().splitlines():
    h, name = line.split()
    pins[name] = h
for line in (pathlib.Path('fixtures/PINS-w183.sha256')).read_text().splitlines():
    h, name = line.split()
    pins[name] = h

lines = []
def check(ok, msg):
    print(('PASS ' if ok else 'FAIL ') + msg)
    lines.append(('PASS ' if ok else 'FAIL ') + msg)
    if not ok:
        raise SystemExit(1)

for tag, value, fixture in cases:
    want_digest = pins[fixture]
    data = (V / fixture if fixture.startswith('mounting') else pathlib.Path('fixtures') / fixture).read_bytes()
    check(hashlib.sha256(data).hexdigest() == want_digest,
          '%s fixture %s sha256 %s' % (tag, fixture, want_digest))
    # KiCad 8.0.8 schIUScale: MilsToIU truncates mils, then IU_PER_MIL = 254.
    # scaled = int(SizeZ * 72 / 10) * 254; the OOB store sets the upper half
    # of the freed chunk's size field, whose low half stays 0x20.
    scaled = int(value * 72 / 10) * 254
    want_size = (scaled << 32) | 0x20
    log = (E / (tag + '.log')).read_text(errors='replace')
    check('received signal SIGABRT, Aborted.' in log and
          'double free or corruption (out)' in log,
          '%s real process SIGABRT in glibc free' % tag)
    check(('size=%d)' % want_size) in log,
          '%s SizeZ=%d -> scaled=0x%x -> chunk size=0x%x (%d)' %
          (tag, value, scaled, want_size, want_size))

ctl = (E / 'w183-control.log').read_bytes()
check(len(ctl) == 0 and (E / 'w183-control.rc').read_text().strip() == 'alive',
      'w183-control unmodified vendor file: empty stderr, process alive')

trace = hashlib.sha256('\n'.join(lines).encode()).hexdigest()
print('PASS=%d FAIL=0' % len(lines))
print('trace %s' % trace)
PY
