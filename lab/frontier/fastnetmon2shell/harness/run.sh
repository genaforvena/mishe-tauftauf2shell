#!/usr/bin/env bash
# Rebuild and replay CVE-2026-48689 from the pinned raw upstream headers.
# No network access at run time: pins/*.hpp are the only parser bytes used.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p ../out-vuln-asan ../out-fixed-asan ../out-vuln-plain ../out-fixed-plain ../evidence

CXX=${CXX:-g++}
COMMON="-std=c++17 -g -O0 -fno-omit-frame-pointer -I../pins"

$CXX $COMMON -fsanitize=address -o poc-vuln-asan poc.cpp || exit 1
$CXX $COMMON -fsanitize=address -DUSE_FIXED -o poc-fixed-asan poc.cpp || exit 1
$CXX $COMMON -o poc-vuln-plain poc.cpp || exit 1
$CXX $COMMON -DUSE_FIXED -o poc-fixed-plain poc.cpp || exit 1

for marker in 41 5a; do
    ./poc-vuln-asan     "0x$marker" > "../out-vuln-asan/$marker.log"     2>&1
    echo "vuln-asan   marker=0x$marker rc=$?"
    ./poc-fixed-asan    "0x$marker" > "../out-fixed-asan/$marker.log"    2>&1
    echo "fixed-asan  marker=0x$marker rc=$?"
    ./poc-vuln-plain    "0x$marker" > "../out-vuln-plain/$marker.log"    2>&1
    echo "vuln-plain  marker=0x$marker rc=$?"
    ./poc-fixed-plain   "0x$marker" > "../out-fixed-plain/$marker.log"   2>&1
    echo "fixed-plain marker=0x$marker rc=$?"
done

# Normalize only volatile fields: PIDs, long (6+ digit) addresses and ASan
# frame numbers. Short chosen-byte hex values (0x41 / 0x5a) are preserved.
for marker in 41 5a; do
    for build in vuln-asan fixed-asan vuln-plain fixed-plain; do
        sed -E \
            -e 's/==[0-9]+==/==PID==/g' \
            -e 's/0x[0-9a-fA-F]{6,}/0xADDR/g' \
            -e 's/#[0-9]+ /#FRAME /g' \
            "../out-$build/$marker.log" > "../evidence/norm-$build-$marker.log"
    done
done
sha256sum ../evidence/norm-*.log | sort -k2 > ../EVIDENCE_HASHES.txt
echo "wrote ../EVIDENCE_HASHES.txt"
