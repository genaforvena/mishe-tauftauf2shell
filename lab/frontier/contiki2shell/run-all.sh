#!/bin/sh
# Three-control replay: vulnerable attack, vulnerable safe input, PR-fixed.
# All traffic is injected into uip_process(); no external network is used.
set -eu
cd "$(dirname "$0")"
sh bootstrap.sh
cd contiki-ng-release-v5.2/examples/multicast

CCARG='gcc -fsanitize=address -g -O0'
LDARG='gcc -fsanitize=address'
BIN=build/native/harness.native
PASS=0
FAIL=0

check() {
  name=$1
  ok=$2
  if [ "$ok" = 1 ]; then
    echo "PASS $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL $name"
    FAIL=$((FAIL + 1))
  fi
}

no_asan() {
  grep -q 'AddressSanitizer' "$1" && echo 0 || echo 1
}

build() {
  make TARGET=native clean >/dev/null 2>&1 || true
  make TARGET=native CONTIKI_PROJECT=harness CC="$CCARG" LD="$LDARG" >/dev/null
}

# 1. Vulnerable build, short S=3 MPL option.
build
set +e
timeout 25 "$BIN" > ../../attack-asan.out 2>&1
attack_rc=$?
set -e
check "attack ASan abort" "$([ "$attack_rc" -eq 1 ] && echo 1 || echo 0)"
check "attack global-buffer-overflow" "$(grep -q 'global-buffer-overflow' ../../attack-asan.out && echo 1 || echo 0)"
check "attack WRITE of size 1232" "$(grep -q 'WRITE of size 1232' ../../attack-asan.out && echo 1 || echo 0)"
check "attack in mpl.c data_message_expiration" "$(grep -q 'data_message_expiration' ../../attack-asan.out && echo 1 || echo 0)"
check "chosen marker in gdb transcript" "$(grep -q '0x4d.*0x49.*0x53.*0x48' ../../../gdb-inspect.txt && echo 1 || echo 0)"

# 2. Vulnerable build, complete S=3 option: no overflow.
set +e
MPL_SAFE=1 timeout 25 "$BIN" > ../../safe-asan.out 2>&1
safe_rc=$?
set -e
check "safe input harness completes" "$([ "$safe_rc" -eq 124 ] && echo 1 || echo 0)"
check "safe input no ASan report" "$(no_asan ../../safe-asan.out)"

# 3. PR #3312 fix applied to the same pinned tree.
cd ../../../contiki-ng-release-v5.2
git apply ../fix-pr3312.patch
cd examples/multicast
build
set +e
timeout 25 "$BIN" > ../../fixed-asan.out 2>&1
fixed_rc=$?
set -e
check "fixed build no ASan report" "$(no_asan ../../fixed-asan.out)"
check "fixed harness completes" "$([ "$fixed_rc" -eq 124 ] && echo 1 || echo 0)"

echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
