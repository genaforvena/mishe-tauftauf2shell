#!/usr/bin/env bash
# Build the committed malloc/free tracer used by Ruby2Shell and Node2Shell.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
gcc -shared -fPIC -O2 -o "$HERE/mtrace.so" "$HERE/mtrace.c"
echo "built $HERE/mtrace.so"
