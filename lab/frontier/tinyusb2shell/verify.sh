#!/bin/sh
# Local-only controls for the TinyUSB HID report-descriptor underflow.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$HERE/evidence"
PASS=0; FAIL=0
check()
{
    label=$1; bin=$2; input=$3; want=$4; log="$HERE/evidence/$5"
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 "$bin" "$input" >"$log" 2>&1
    rc=$?
    body=$(cat "$log")
    case "$want" in
        asan-read) case "$body" in
            *"AddressSanitizer"*"READ of size"*) ok=1;; *) ok=0;; esac;;
        asan-write) case "$body" in
            *"AddressSanitizer"*"WRITE of size"*) ok=1;; *) ok=0;; esac;;
        clean-zero) case "$body" in
            *AddressSanitizer*) ok=0;; *"report_num=0"*) ok=1;; *) ok=0;; esac;;
        clean) case "$body" in
            *AddressSanitizer*) ok=0;; *"report_num="*) ok=1;; *) ok=0;; esac;;
    esac
    if [ "$ok" = 1 ]; then PASS=$((PASS+1)); echo "PASS $label rc=$rc log=$log";
    else FAIL=$((FAIL+1)); echo "FAIL $label rc=$rc log=$log"; fi
}
check vuln-attack-asan-read "$HERE/build/vuln/driver" attack asan-read vuln-asan-attack.out
check fixed-attack-clean-zero "$HERE/build/fixed/driver" attack clean-zero fixed-asan-attack.out
check vuln-width-asan-write "$HERE/build/vuln/driver" width asan-write vuln-asan-width.out
check fixed-width-clean "$HERE/build/fixed/driver" width clean fixed-asan-width.out
check vuln-safe-clean "$HERE/build/vuln/driver" safe clean vuln-asan-safe.out
check fixed-safe-clean "$HERE/build/fixed/driver" safe clean fixed-asan-safe.out
echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
