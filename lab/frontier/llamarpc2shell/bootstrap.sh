#!/bin/sh
# Rebuild both variants from the pinned upstream files. No network, no RDMA
# device, no host configuration changes.
set -eu
cd "$(dirname "$0")"
sha256sum -c pins.sha256
rm -rf vuln-src fixed-src
mkdir -p vuln-src fixed-src
for f in transport.cpp transport.h log.h; do
    cp "src/$f" "vuln-src/$f"
    cp "src/$f" "fixed-src/$f"
done
(cd fixed-src && patch -p1 < ../fix-rdma-recv.patch)
CXX=${CXX:-g++}
COMMON="-std=c++17 -DGGML_RPC_RDMA -I shim -I src -O0 -g -fno-omit-frame-pointer"
# shellcheck disable=SC2086
$CXX $COMMON -fsanitize=address harness.cpp vuln-src/transport.cpp -o vuln-asan
# shellcheck disable=SC2086
$CXX $COMMON -fsanitize=address harness.cpp fixed-src/transport.cpp -o fixed-asan
# shellcheck disable=SC2086
$CXX $COMMON harness.cpp vuln-src/transport.cpp -o vuln-plain
# shellcheck disable=SC2086
$CXX $COMMON harness.cpp fixed-src/transport.cpp -o fixed-plain
echo "bootstrap OK"
