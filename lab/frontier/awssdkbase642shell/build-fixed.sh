#!/bin/sh
# Fixed-arm control: patched Base64.cpp delegating to the pinned fixed
# aws-crt-cpp v0.43.2 Types.cpp and pinned aws-c-common encoding path.
# Requires build-real.sh to have extracted the pinned archives first.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p work runs

CRT=work/crt-fixed/aws-crt-cpp-0463563f9f656a493ec22ca962c2464bc8b831ab
COMMON=work/common/aws-c-common-3c69b871dfa1815231802febf1bb6899f84cccdb
PARENT=work/sdk/aws-sdk-cpp-2857dbc70b4b780810e304ba14514fa52d932a23/src/aws-cpp-sdk-core
FIX=work/fixed/src/aws-cpp-sdk-core

if [ ! -d "$CRT" ]; then
    mkdir -p work/crt-fixed
    tar -xzf pins/crt-fixed-source.tar.gz -C work/crt-fixed
fi

if ! grep -q 'Aws::Crt::Base64Decode' "$FIX/source/utils/base64/Base64.cpp" 2>/dev/null; then
    mkdir -p "$FIX/source/utils/base64" "$FIX/include/aws/core/utils/base64"
    cp "$PARENT/source/utils/base64/Base64.cpp" "$FIX/source/utils/base64/Base64.cpp"
    cp "$PARENT/include/aws/core/utils/base64/Base64.h" "$FIX/include/aws/core/utils/base64/Base64.h"
    # Only the two base64 files exist in the staging tree; patch skips the
    # sibling hunks (crt submodule, prefetch script, gtest) by design.
    (cd work/fixed && patch -p1 -f < ../../pins/fix.patch) > runs/fixed-patch.log 2>&1 || true
    grep -q 'Aws::Crt::Base64Decode' "$FIX/source/utils/base64/Base64.cpp" || {
        echo PATCH_FAIL_BASE64; exit 3;
    }
fi

for f in encoding allocator byte_buf error string array_list assert; do
    gcc -std=c99 -g -O0 -fsanitize=address -I "$COMMON/include" -I harness/generated \
        -c "$COMMON/source/$f.c" -o "work/fixed-$f.o"
done

INCS=$(find work -type d -name include -print | while read -r d; do printf -- '-I %s ' "$d"; done)
g++ -std=c++11 -g -O0 -DNDEBUG -fsanitize=address -ffunction-sections -fdata-sections \
    -I "$FIX/include" -I "$CRT/include" $INCS -I harness/generated -Wl,--gc-sections \
    -o work/decode-fixed-asan \
    harness/decode_harness.cpp harness/fixed_crt_shim.cpp \
    "$FIX/source/utils/base64/Base64.cpp" "$CRT/source/Types.cpp" \
    work/fixed-encoding.o work/fixed-allocator.o work/fixed-byte_buf.o \
    work/fixed-error.o work/fixed-string.o work/fixed-array_list.o work/fixed-assert.o

echo BUILD_OK decode-fixed-asan
