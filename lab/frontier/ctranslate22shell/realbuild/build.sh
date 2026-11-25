#!/bin/sh
# Reproduce the real-source CTranslate2 v4.8.0 Model::load consumer.
# Provisioning (curl to GitHub) is done once; the script itself is offline.
set -eu
cd "$(dirname "$0")"
SRC=src/CTranslate2-4.8.0
INC="-I$SRC/include -I$SRC/third_party -Ishim -I$SRC/src"
COMMON="harness/driver.cpp harness/stubs.cpp"
REAL="$SRC/src/models/model_reader.cc $SRC/src/storage_view.cc $SRC/src/allocator.cc \
$SRC/src/cpu/allocator.cc $SRC/src/cpu/primitives.cc $SRC/src/cpu/backend.cc \
$SRC/src/cpu/cpu_isa.cc $SRC/src/cpu/kernels.cc $SRC/src/env.cc $SRC/src/types.cc \
$SRC/src/devices.cc"
FLAGS="-std=c++17 -O0 -g -ffunction-sections -fdata-sections -DCT2_X86_BUILD $INC -Wl,--gc-sections"

# Vulnerable, ASan: real upstream src/models/model.cc verbatim.
g++ $FLAGS -fsanitize=address -fno-omit-frame-pointer $COMMON "$SRC/src/models/model.cc" $REAL -o consumer-asan
# Fixed control: upstream fix d9b991e model.cc verbatim, same harness.
g++ $FLAGS -fsanitize=address -fno-omit-frame-pointer $COMMON src/model-fixed.cc $REAL -o consumer-fixed-asan
# Plain build: chosen-byte / heap-metadata observation without ASan.
g++ $FLAGS $COMMON "$SRC/src/models/model.cc" $REAL -o consumer-plain

mkdir -p evidence
ASAN_OPTIONS=abort_on_error=0:symbolize=1 ./consumer-asan 17 > evidence/real-asan-17.out 2>&1 || true
ASAN_OPTIONS=abort_on_error=0:symbolize=1 ./consumer-asan 16 > evidence/real-asan-16.out 2>&1 || true
ASAN_OPTIONS=abort_on_error=0:symbolize=1 ./consumer-asan 48 > evidence/real-asan-48.out 2>&1 || true
ASAN_OPTIONS=abort_on_error=0:symbolize=1 ./consumer-fixed-asan 17 > evidence/fixed-asan-17.out 2>&1 || true
for n in 16 48 64 80; do ./consumer-plain "$n" > "evidence/plain-$n.out" 2>&1 || true; done
printf 'sha256 of model.cc pins:\n'
sha256sum "$SRC/src/models/model.cc" src/model-fixed.cc
