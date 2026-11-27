#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p harness/bin
CC=${CC:-clang}
for arm in vuln fixed; do
  "$CC" -std=c11 -O1 -g -fsanitize=address -fno-omit-frame-pointer \
    -DSBAT_SOURCE=\"../src/$arm/sbat.inc\" \
    harness/driver.c -o "harness/bin/${arm}-asan"
  "$CC" -std=c11 -O0 -g -fno-stack-protector -fno-pie -no-pie \
    -DWRAP_CALLOC -Wl,--wrap=calloc \
    -DSBAT_SOURCE=\"../src/$arm/sbat.inc\" \
    harness/driver.c -o "harness/bin/${arm}-marker"
done
