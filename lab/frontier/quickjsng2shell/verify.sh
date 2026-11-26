#!/bin/sh
# Re-check saved QuickJS-NG runner evidence without rebuilding.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
PASS=0
FAIL=0
has() { if grep -qF "$2" "$1"; then PASS=$((PASS+1)); echo "PASS $3"; else FAIL=$((FAIL+1)); echo "FAIL $3"; fi; }
hasnt() { if grep -qF "$2" "$1"; then FAIL=$((FAIL+1)); echo "FAIL $3"; else PASS=$((PASS+1)); echo "PASS $3"; fi; }

has evidence/vuln-asan-poc.out 'ERROR: AddressSanitizer: heap-use-after-free' "vuln UAF"
has evidence/vuln-asan-poc.out 'READ of size 4' "vuln READ-4"
has evidence/vuln-asan-poc.out 'js_dup build/vuln/quickjs.c:1546' "vuln js_dup frame"
has evidence/vuln-asan-poc.out 'js_get_fast_array_element build/vuln/quickjs.c:9478' "vuln fast-array frame"
has evidence/vuln-asan-poc.out '0 bytes inside of 72-byte region' "vuln freed boundary"
has evidence/fixed-asan-poc.out 'undefined' "fixed empty slot"
hasnt evidence/fixed-asan-poc.out 'AddressSanitizer' "fixed no ASan"
for side in vuln fixed; do
    has "evidence/$side-asan-safe.out" '[1,2]' "$side safe readback"
    hasnt "evidence/$side-asan-safe.out" 'AddressSanitizer' "$side safe clean"
done
echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
