#!/bin/bash
# Build the jemalloc-aware allocation tracer atomically.
set -eu
cd "$(dirname "$0")"
tmp="$(mktemp jemtrace.XXXXXX.so)"
gcc -shared -fPIC -O2 -o "$tmp" jemtrace.c -ldl
chmod 644 "$tmp"
mv -f "$tmp" jemtrace.so
echo "built lab/preload/jemtrace.so"
