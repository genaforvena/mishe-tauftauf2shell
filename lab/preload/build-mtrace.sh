#!/usr/bin/env bash
# Build the committed malloc/free tracer used by Ruby2Shell and Node2Shell.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp "$HERE/.mtrace.so.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
gcc -shared -fPIC -O2 -o "$TMP" "$HERE/mtrace.c"
mv -f "$TMP" "$HERE/mtrace.so"
trap - EXIT
echo "built $HERE/mtrace.so"
