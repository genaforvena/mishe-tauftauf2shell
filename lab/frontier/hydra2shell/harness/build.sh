#!/bin/sh
# Build direct-call harnesses from pinned blobs. No network access.
set -eu
cd "$(dirname "$0")/.."
: "${CC:=gcc}"
base=$(basename "$CC")
$CC -std=gnu11 -O0 -g -I. -fno-omit-frame-pointer \
  -DFUNC_FILE='"src/analyze-v9.7.c"' -fsanitize=address \
  harness/harness.c -o "harness/${base}-vuln-asan"
$CC -std=gnu11 -O0 -g -I. -fno-omit-frame-pointer \
  -DFUNC_FILE='"src/analyze-v9.7.c"' \
  harness/harness.c -o "harness/${base}-vuln-plain"
$CC -std=gnu11 -O0 -g -I. -fno-omit-frame-pointer \
  -DFUNC_FILE='"src/analyze-fixed.c"' -fsanitize=address \
  harness/harness.c -o "harness/${base}-fixed-asan"
$CC -std=gnu11 -O0 -g -I. -fno-omit-frame-pointer \
  -DFUNC_FILE='"src/analyze-fixed.c"' \
  harness/harness.c -o "harness/${base}-fixed-plain"
