#!/bin/sh
# Local-only controls for the Axis2/C Guththila event_map OOB read.
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
        asan) case "$body" in
            *"AddressSanitizer: heap-buffer-overflow"*"guththila_xml_reader_wrapper.c:308"*) ok=1;; *) ok=0;; esac;;
        clean-minus1) case "$body" in
            *AddressSanitizer*) ok=0;; *"event[0]=-1"*) ok=1;; *) ok=0;; esac;;
        clean) case "$body" in
            *AddressSanitizer*) ok=0;; *"event[0]="*) ok=1;; *) ok=0;; esac;;
    esac
    if [ "$ok" = 1 ]; then PASS=$((PASS+1)); echo "PASS $label rc=$rc log=$log";
    else FAIL=$((FAIL+1)); echo "FAIL $label rc=$rc log=$log"; fi
}
ATK='<!ENTITY x "y"><a/>'
SAFE='<a>text</a>'
check vuln-attack-asan "$HERE/build/vuln/driver" "$ATK" asan vuln-asan-attack.out
check fixed-attack-clean "$HERE/build/fixed/driver" "$ATK" clean-minus1 fixed-asan-attack.out
check vuln-safe-clean "$HERE/build/vuln/driver" "$SAFE" clean vuln-asan-safe.out
check fixed-safe-clean "$HERE/build/fixed/driver" "$SAFE" clean fixed-asan-safe.out
echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
