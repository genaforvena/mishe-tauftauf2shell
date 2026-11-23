#!/bin/sh
# W170: replay the plain glibc OOB-source measurement from the lab root.
# Needs bin-vuln-plain/flat_harness (see BUILDLOG.md) and gdb.
set -eu
cd "$(dirname "$0")/.."
python3 cases/make_poc.py cases/baseline.exr cases/poc5a.exr 1024 64 0x5a >/dev/null
gdb -q -batch -x harness/gdb-oob-src.cmd --args ./bin-vuln-plain/flat_harness > bin-vuln-plain/gdb-oob-r1.out 2>&1 || true
cp harness/gdb-oob-src.cmd bin-vuln-plain/gdb-oob-src-r2.cmd
python3 - <<'PY'
p = 'bin-vuln-plain/gdb-oob-src-r2.cmd'
s = open(p).read().replace('oob-src.bin', 'oob-src-r2.bin').replace('oob-dst.bin', 'oob-dst-r2.bin')
open(p, 'w').write(s)
PY
gdb -q -batch -x bin-vuln-plain/gdb-oob-src-r2.cmd --args ./bin-vuln-plain/flat_harness > bin-vuln-plain/gdb-oob-r2.out 2>&1 || true
gdb -q -batch -x harness/gdb-oob-src5a.cmd --args ./bin-vuln-plain/flat_harness > bin-vuln-plain/gdb-oob-5a.out 2>&1 || true
grep -h '^SINK' bin-vuln-plain/gdb-oob-r1.out bin-vuln-plain/gdb-oob-r2.out bin-vuln-plain/gdb-oob-5a.out
python3 harness/analyze_oob_source.py \
    bin-vuln-plain/oob-src.bin bin-vuln-plain/oob-src-r2.bin bin-vuln-plain/oob-src5a.bin
