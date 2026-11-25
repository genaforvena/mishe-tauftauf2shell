#!/bin/sh
# W6: stock block-config negative in the real pinned Connection::ProcessPacket.
# Copies the witness tree; never edits lab/frontier/yojimbo2shell/upstream/.
set -eu
cd "$(dirname "$0")"
mkdir -p upstream-defaultcfg harness/evidence
tar -C upstream --exclude='./build-*' --exclude='./bin' --exclude='./.git' -cf - . | tar -C upstream-defaultcfg -xf -
patch -d upstream-defaultcfg -p1 < defaultcfg-test.patch
cmake -S upstream-defaultcfg -B upstream-defaultcfg/build-asan-vuln -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g' \
  -DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' > defaultcfg-config.log 2>&1
cmake --build upstream-defaultcfg/build-asan-vuln --target test -j2 > defaultcfg-build.log 2>&1
set +e
ASAN_OPTIONS=detect_leaks=0 upstream-defaultcfg/bin/test 1795576058 \
  > harness/evidence/defaultcfg-asan.out 2>&1
RC=$?
set -e
grep -q 'MISHE-DEFAULT-CFG accepted maxBlockSize=262144 fragmentSize=1024 fragmentId=255 packetBytes=1030' harness/evidence/defaultcfg-asan.out
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' harness/evidence/defaultcfg-asan.out
grep -q 'WRITE of size 500' harness/evidence/defaultcfg-asan.out
grep -q 'yojimbo::ReliableOrderedChannel::ProcessPacketFragment' harness/evidence/defaultcfg-asan.out
printf 'DEFAULT-CFG NEGATIVE OK: stock fragment accepted, 1100/500 control faults (rc=%d)\n' "$RC"
