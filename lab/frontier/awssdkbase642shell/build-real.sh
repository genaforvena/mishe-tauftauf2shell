#!/bin/sh
# Offline rebuild of the AWS SDK C++ Base64 decoder consumers from pinned archives.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p work

extract() {
    archive=$1
    dir=$2
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        tar -xzf "pins/$archive" -C "$dir"
    fi
}
extract source-parent.tar.gz work/sdk
extract crt-source.tar.gz work/crt
extract common-source.tar.gz work/common
extract io-source.tar.gz work/io
extract mqtt-source.tar.gz work/mqtt
extract http-source.tar.gz work/http
extract auth-source.tar.gz work/auth
extract event-stream-source.tar.gz work/event-stream
extract s3-source.tar.gz work/s3
extract sdkutils-source.tar.gz work/sdkutils
extract checksums-source.tar.gz work/checksums
extract cal-source.tar.gz work/cal
extract compression-source.tar.gz work/compression

SRC=$(find work/sdk -type d -path '*/src/aws-cpp-sdk-core' | head -1)
INCS=$(find work -type d -name include -print | while read -r d; do printf -- '-I %s ' "$d"; done)

build_one() {
    label=$1
    shift
    g++ -std=c++11 -g -O0 -fno-omit-frame-pointer $INCS -I harness/generated \
        -I "$SRC/include" "$@" -o "work/$label" \
        harness/decode_harness.cpp "$SRC/source/utils/base64/Base64.cpp"
    echo "BUILD_OK $label"
}

build_one decode-debug-asan -fsanitize=address
build_one decode-asan -DNDEBUG -fsanitize=address
build_one decode-plain -DNDEBUG
