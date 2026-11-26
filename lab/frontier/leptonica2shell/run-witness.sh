#!/usr/bin/env bash
# One-command clean-archive replay of both leptonica2shell lanes.
# Run from anywhere in the checkout: bash lab/frontier/leptonica2shell/run-witness.sh [OUTDIR]
# Prints "WITNESS REPLAY PASS" only if every hash and staged/real control holds.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || true)
if [ -n "$ROOT" ]; then
  OUT=${1:-$(mktemp -d -t leptonica-witness.XXXXXX)}
  mkdir -p "$OUT"
  git -C "$ROOT" archive HEAD lab/frontier/leptonica2shell | tar -x -C "$OUT"
  echo "CLEAN_ARCHIVE=$OUT HEAD=$(git -C "$ROOT" rev-parse HEAD)"
  HERE="$OUT/lab/frontier/leptonica2shell"
fi
cd "$HERE"
mkdir -p out

fail=0
ok() { printf 'PASS %s\n' "$1"; }
no() { printf 'FAIL %s\n' "$1"; fail=$((fail+1)); }
hashcheck() { # FILE EXPECTED_SHA256 LABEL
  got=$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)
  if [ "$got" = "$2" ]; then ok "$3"; else no "$3 (got $got)"; fi
}
need() { # FILE PATTERN LABEL
  if grep -q "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
need_not() {
  if grep -q "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}

echo '== staged pins and runner'
hashcheck pins/bytearray-1.87.0.c b5740bbd65a5a7d18fa60220138411a5cc72ad838045e86d015889d835eccbc7 'staged vulnerable bytearray.c'
hashcheck pins/bytearray-fixed.c e37f74fd680a917bc5c37a9b54d51e6ab242dd26fea6c30017e88c1b50e96e65 'staged fixed bytearray.c'
hashcheck pins/array_internal-1.87.0.h 6503883af8155c4e57daad609f8efdccc67d1c64b8ed6f8501cf0adc580d8fb7 'staged array_internal.h excerpt'
hashcheck pins/consts.inc 25bd8f0a16b28e694ea55ea473fbe099858b42ab29e3db5ea6ac322d8d2462d9 'staged constants excerpt'
hashcheck pins/create-parent.inc 571570525a8cbb69488c1a3a31b0390a25f11fa9f0e357eac558f30105bbb685 'staged vulnerable l_byteaCreate'
hashcheck pins/stream-parent.inc 5ed99ee58e3aac5be7906668a7266c9c60e880846d9b62123b1a7843c0dad32b 'staged vulnerable l_byteaInitFromStream'
hashcheck pins/create-fixed.inc a66cebd7340cecb55950175418ef0b4c353485e74b2b28becb0778f10d0f7a6f 'staged fixed l_byteaCreate'
hashcheck pins/stream-fixed.inc b05ae0baca694553e4b4657fdfeb8f69bb0f356f3e160c5d2b2cbe0dac168eaf 'staged fixed l_byteaInitFromStream'
hashcheck run-all.sh e4a634256369c276576eb4001f0bdd7f0c4fd1e8d0e4910915bced89ae59b6d3 'staged runner'

echo '== real scripts'
hashcheck real/provision.sh 073c55d82e852cb53ee8db3058308c87e5f3a8fed0064c184062d94911b9b789 'real provisioner'
hashcheck real/run-real.sh ce0a0ae3c109bd3561281fb966b55eeeae424f0b8e18402f1d34751e18b4e4f7 'real ASan runner'
hashcheck real/run-neighbor.sh d37b459cad45ffb87bf2013c3065a938e9069d47cc8b3e54e575a0e3c29a5101 'plain neighbor runner'
hashcheck real/neighbor.c 4cf69a40567efd8a2f577bf848348833ef48d02c139f5b8e00a89c6592e9971b 'plain neighbor observer'

echo '== staged runner (17 PASS / 0 FAIL expected)'
if bash run-all.sh > out/witness-staged.log 2>&1; then
  ok "staged runner $(tail -1 out/witness-staged.log)"
else
  no "staged runner $(tail -1 out/witness-staged.log)"
fi
need out/witness-staged.log 'TOTAL: 17 PASS / 0 FAIL' 'staged total'
need harness/out/vuln-asan.out 'WRITE of size 1000000001' 'staged GCC ASan WRITE'
need harness/out/vuln-clang-asan.out 'WRITE of size 1000000001' 'staged Clang ASan WRITE'
need harness/out/vuln-plain.out 'PAST_ALLOC=4d495348452d4c4550544f4e49434111' 'staged bounded chosen-byte readback'
need_not harness/out/fixed-asan.out 'AddressSanitizer' 'staged fixed control clean'

echo '== real ASan runner (7 PASS / 0 FAIL expected)'
if bash real/provision.sh > out/witness-provision.log 2>&1; then
  ok "real provisioner $(tail -1 out/witness-provision.log)"
else
  no "real provisioner $(tail -1 out/witness-provision.log)"
fi
need out/witness-provision.log 'TOTAL: 7 PASS / 0 FAIL' 'real ASan total'
hashcheck real/src/src/bytearray.c b5740bbd65a5a7d18fa60220138411a5cc72ad838045e86d015889d835eccbc7 'real vulnerable upstream bytes'
hashcheck real/src-fixed/src/bytearray.c e37f74fd680a917bc5c37a9b54d51e6ab242dd26fea6c30017e88c1b50e96e65 'real fixed upstream bytes'
need real/evidence/real-vuln-asan.out 'WRITE of size 1000000001' 'real ASan WRITE'
need real/evidence/real-vuln-asan.out 'bytearray.c:192' 'real write frame in pinned function'
need real/evidence/real-vuln-asan.out 'bytearray.c:105' 'real allocation frame'
need real/evidence/real-caller-asan.out 'saConcatenatePdfToData' 'real in-library caller'
need real/evidence/real-fixed-asan.out 'BA=NULL' 'real fixed control rejects'
need_not real/evidence/real-fixed-asan.out 'AddressSanitizer' 'real fixed control clean'
need real/evidence/real-vuln-safe.out 'SIZE=16' 'real safe control'

echo '== plain real neighbor (5 PASS / 0 FAIL expected)'
if bash real/run-neighbor.sh > out/witness-neighbor.log 2>&1; then
  ok "plain neighbor $(tail -1 out/witness-neighbor.log)"
else
  no "plain neighbor $(tail -1 out/witness-neighbor.log)"
fi
need out/witness-neighbor.log 'TOTAL: 5 PASS / 0 FAIL' 'plain neighbor total'
need real/evidence/neighbor-plain-attack.out 'SIGNAL=SIGSEGV' 'plain oversized stream faults'
need real/evidence/neighbor-plain-attack.out 'CHOSEN_AT_OFFSET=16' 'chosen bytes in live sentinel'
need real/evidence/neighbor-plain-attack.out 'FAULT_OFFSET_FROM_DATA=129504' 'measured heap-mapping fault boundary'
need real/evidence/neighbor-plain-safe.out 'NO_FAULT=1' 'plain safe control intact'
need_not real/evidence/neighbor-plain-safe.out 'SIGNAL=' 'plain safe control no fault'

if [ "$fail" -eq 0 ]; then
  printf 'WITNESS REPLAY PASS\n'
else
  printf 'WITNESS REPLAY FAIL (%s)\n' "$fail"
fi
exit "$fail"
