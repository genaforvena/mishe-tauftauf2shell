#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p harness/bin
CXX=${CXX:-clang++}
for arm in vuln fixed; do
  defs=()
  if [[ "$arm" == fixed ]]; then defs+=(-DFIXED); fi
  "$CXX" -std=c++20 -O1 -g -fsanitize=address -fno-omit-frame-pointer \
    "${defs[@]}" -DMKEVENT_SOURCE=\"../src/$arm/mkevent.cc\" \
    harness/driver.cc -o "harness/bin/${arm}-asan"
  "$CXX" -std=c++20 -O0 -g -fno-stack-protector -fno-pie -no-pie \
    "${defs[@]}" -DMKEVENT_SOURCE=\"../src/$arm/mkevent.cc\" \
    harness/driver.cc -o "harness/bin/${arm}-plain"
done

"$CXX" -std=c++20 -O0 -g -fno-stack-protector -fno-pie -no-pie \
  -DMKEVENT_SOURCE=\"../src/vuln/mkevent.cc\" \
  harness/direct_driver.cc -o harness/bin/vuln-direct-plain
