#!/bin/sh
# Build the generated REST-JSON client model caller for both arms. Requires
# build-real.sh (pinned sources) and build-fixed.sh (fixed CRT + common objects).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p work

SDK=work/sdk/aws-sdk-cpp-2857dbc70b4b780810e304ba14514fa52d932a23
GEN=$SDK/generated/protocol-tests/test-clients/aws-cpp-sdk-rest-json-protocol
CORE=$SDK/src/aws-cpp-sdk-core
CRT=work/crt-fixed/aws-crt-cpp-0463563f9f656a493ec22ca962c2464bc8b831ab
FIX=work/fixed/src/aws-cpp-sdk-core
INCS=$(find work -type d -name include -print | while read -r d; do printf -- '-I %s ' "$d"; done)
COMMON_FLAGS='-std=c++11 -g -O0 -DNDEBUG -fsanitize=address -ffunction-sections -fdata-sections -Wl,--gc-sections'
MODEL="$GEN/source/model/JsonBlobsResult.cpp"
HASH="$CORE/source/utils/HashingUtils.cpp"
JSON="$CORE/source/utils/json/JsonSerializer.cpp"
CJSON="$CORE/source/external/cjson/cJSON.cpp"

# Vulnerable arm: unmodified pinned Base64.cpp.
g++ $COMMON_FLAGS -I "$CORE/include" -I "$CORE/source/external/cjson" \
    -I "$GEN/include" $INCS -I harness/generated \
    -o work/generated-client-asan harness/generated_client_harness.cpp \
    "$MODEL" "$CORE/source/utils/base64/Base64.cpp" "$HASH" "$JSON" "$CJSON"
echo BUILD_OK generated-client-asan

# Fixed arm: patched Base64.cpp + fixed CRT Types.cpp + pinned common.
g++ $COMMON_FLAGS -I "$FIX/include" -I "$CRT/include" -I "$CORE/include" \
    -I "$CORE/source/external/cjson" -I "$GEN/include" $INCS -I harness/generated \
    -o work/generated-client-fixed-asan harness/generated_client_harness.cpp \
    "$MODEL" "$FIX/source/utils/base64/Base64.cpp" "$HASH" "$JSON" "$CJSON" \
    "$CRT/source/Types.cpp" harness/fixed_crt_shim.cpp \
    work/fixed-encoding.o work/fixed-allocator.o work/fixed-byte_buf.o \
    work/fixed-error.o work/fixed-string.o work/fixed-array_list.o work/fixed-assert.o
echo BUILD_OK generated-client-fixed-asan
