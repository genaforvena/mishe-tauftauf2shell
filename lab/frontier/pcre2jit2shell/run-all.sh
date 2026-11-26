#!/bin/sh
# Frontier lab runner - PCRE2 CVE-2026-103111 / GHSA-r9hj-j2rw-4q3m.
# Public tarballs, published patch, hash-matched advisory PoC; local builds
# only. No network probe, no external target, no socket, no command execution.
set -u
ulimit -c 0 2>/dev/null || true
cd "$(dirname "$0")" || exit 2

V_TAR=src/pcre2-10.48.tar.gz
F_TAR=src/pcre2-10.49.tar.gz
V_TAR_SHA=ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888
F_TAR_SHA=929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae
PATCH_SHA=38f740cb52919619945f3cf4b68a7c0892f68b564ef14879266781ee70b4165f
POC_SHA=2bda01bc0d70ac7888a8205aa9141e4bf8efcc0e7b48cc50eb23adca56756cd4
REG_SHA=50be5b8ef5b1c3d4894754f055ba9d7c0c00571a0724f4f29b9851e3f482c38b
V_SRC_SHA=60cb5be780844af9edbcda95010478afe56e95623bccb677b29113b4552321c8
F_SRC_SHA=32b4f057cc8ac9a15c9c837121112329e866c1bc1d98acce148ceeff4525c587
PASS=0
FAIL=0

sha() { sha256sum "$1" | cut -d' ' -f1; }
ok() { PASS=$((PASS + 1)); echo "PASS $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2' want '$3')"; fi; }
has() { if grep -qF "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -qF "$2" "$1"; then bad "$3"; else ok "$3"; fi; }
number() { awk -v needle="$2" '$0 ~ needle {for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) {print $i; exit}}' "$1"; }

# A valid physical run needs the victim mapping placed immediately below the
# JIT stack; on Linux that reservation can collide under ASLR. Collisions are
# preserved as evidence/replay/<label>-collision-N.out, never counted as passes.
valid_run() {
    label=$1
    bin=$2
    shift 2
    n=1
    while [ "$n" -le 30 ]; do
        "$bin" "$@" > "evidence/replay/$label-try-$n.out" 2>&1
        rc=$?
        if grep -qF 'cannot reserve' "evidence/replay/$label-try-$n.out"; then
            n=$((n + 1))
            continue
        fi
        cp "evidence/replay/$label-try-$n.out" "evidence/replay/$label.out"
        echo "$rc" > "evidence/replay/$label.rc"
        echo "$n" > "evidence/replay/$label.tries"
        ok "valid physical run $label (try $n, rc $rc)"
        return 0
    done
    bad "valid physical run $label (30 placement collisions)"
    echo 99 > "evidence/replay/$label.rc"
    return 1
}

for pair in "$V_TAR:$V_TAR_SHA" "$F_TAR:$F_TAR_SHA" "src/fix.patch:$PATCH_SHA" \
            "src/poc-upstream.c:$POC_SHA" "evidence/regression-input.txt:$REG_SHA"; do
    f=${pair%%:*}
    h=${pair#*:}
    if [ -f "$f" ]; then expect_eq "pin $f" "$(sha "$f")" "$h"; else bad "pin $f present"; fi
done

rm -rf replay-build out evidence/replay
mkdir -p replay-build/vuln replay-build/fixed out evidence/replay
tar xzf "$V_TAR" -C replay-build/vuln --strip-components=1 || bad "extract $V_TAR"
tar xzf "$F_TAR" -C replay-build/fixed --strip-components=1 || bad "extract $F_TAR"
expect_eq "vulnerable pcre2_jit_compile.c" "$(sha replay-build/vuln/src/pcre2_jit_compile.c)" "$V_SRC_SHA"
expect_eq "fixed pcre2_jit_compile.c" "$(sha replay-build/fixed/src/pcre2_jit_compile.c)" "$F_SRC_SHA"
(cd replay-build/vuln && patch --dry-run -p1 < ../../src/fix.patch > ../../out/patch-dry-run.log 2>&1) \
    && ok "upstream fix patch applies cleanly to pinned 10.48" \
    || bad "upstream fix patch applies cleanly to pinned 10.48"
hasnt replay-build/vuln/src/pcre2_jit_compile.c 'large_stack_allocation' "vuln lacks fix flag"
has replay-build/fixed/src/pcre2_jit_compile.c 'large_stack_allocation' "fixed has fix flag"

for side in vuln fixed; do
    (cd "replay-build/$side" && \
        ./configure --enable-jit --disable-shared --enable-static \
            > "../configure-$side.log" 2>&1 && \
        make -j4 pcre2test > "../make-$side.log" 2>&1) \
        && ok "plain JIT build $side" || bad "plain JIT build $side"
done

for side in vuln fixed; do
    cc -O2 -Wall -Wextra "-Ireplay-build/$side" src/poc-upstream.c \
        "replay-build/$side/.libs/libpcre2-8.a" -lm -lpthread \
        -o "out/poc-$side" > "out/cc-$side.log" 2>&1 \
        && ok "compile advisory PoC $side" || bad "compile advisory PoC $side"
done
cc -O2 -Wall -Wextra -DUNIQUE_CAPTURES=100 -Ireplay-build/vuln src/poc-upstream.c \
    replay-build/vuln/.libs/libpcre2-8.a -lm -lpthread \
    -o out/poc-small > out/cc-small.log 2>&1 \
    && ok "compile small-frame control" || bad "compile small-frame control"

valid_run vuln-jit ./out/poc-vuln --physical
valid_run vuln-nojit ./out/poc-vuln --physical --no-jit
valid_run vuln-small ./out/poc-small --physical
valid_run fixed-jit ./out/poc-fixed --physical
valid_run fixed-nojit ./out/poc-fixed --physical --no-jit
# Upstream regression line in fix.patch, via the shipped pcre2test CLI:
# vulnerable 10.48 faults, fixed 10.49 returns the JIT stack-limit error.
"./replay-build/vuln/pcre2test" evidence/regression-input.txt \
    > out/pcre2test-vuln.out 2>&1
V_CLI_RC=$?
"./replay-build/fixed/pcre2test" evidence/regression-input.txt \
    > out/pcre2test-fixed.out 2>&1
F_CLI_RC=$?
has out/pcre2test-vuln.out 'Segmentation fault' "shipped CLI regression vuln faults"
if [ "$V_CLI_RC" -ge 128 ]; then ok "shipped CLI regression vuln rc $V_CLI_RC"; else bad "shipped CLI regression vuln rc $V_CLI_RC"; fi
has out/pcre2test-fixed.out 'JIT stack limit reached' "shipped CLI regression fixed"
if [ "$F_CLI_RC" -eq 0 ]; then ok "shipped CLI regression fixed rc0"; else bad "shipped CLI regression fixed rc $F_CLI_RC"; fi
R=evidence/replay
has "$R/vuln-jit.out" 'PCRE2=10.48 2026-08-31 mode=physical engine=jit' "vuln JIT binary version and engine"
has "$R/vuln-jit.out" 'pcre2_match returned -46' "vuln JIT stack-limit return"
CHANGED=$(number "$R/vuln-jit.out" 'victim bytes clobbered')
DEEP=$(number "$R/vuln-jit.out" 'deepest write')
PTRS=$(number "$R/vuln-jit.out" 'aligned words holding a pointer')
if [ "${CHANGED:-0}" -ge 100000 ]; then ok "vuln victim bytes clobbered $CHANGED"; else bad "vuln victim bytes clobbered ${CHANGED:-none}"; fi
if [ "${DEEP:-0}" -ge 130000 ]; then ok "vuln deepest write $DEEP bytes below mapping"; else bad "vuln deepest write ${DEEP:-none}"; fi
if [ "${PTRS:-0}" -ge 1 ]; then ok "vuln subject-buffer pointers in victim $PTRS"; else bad "vuln subject-buffer pointers ${PTRS:-none}"; fi
expect_eq "vuln JIT PoC exit code" "$(cat "$R/vuln-jit.rc")" "0"

has "$R/vuln-nojit.out" 'pcre2_match returned 2' "vuln interpreter match succeeds"
has "$R/vuln-nojit.out" 'victim bytes clobbered: 0' "vuln interpreter victim clean"
has "$R/vuln-nojit.out" 'aligned words holding a pointer into the subject buffer: 0' "vuln interpreter no pointers"
expect_eq "vuln interpreter exit code" "$(cat "$R/vuln-nojit.rc")" "0"

has "$R/vuln-small.out" 'pcre2_match returned 2' "small frame match succeeds"
has "$R/vuln-small.out" 'victim bytes clobbered: 0' "small frame victim clean"
expect_eq "small frame exit code" "$(cat "$R/vuln-small.rc")" "1"

has "$R/fixed-jit.out" 'PCRE2=10.49 2026-09-28 mode=physical engine=jit' "fixed JIT binary version and engine"
has "$R/fixed-jit.out" 'pcre2_match returned -46' "fixed JIT stack-limit return"
has "$R/fixed-jit.out" 'victim bytes clobbered: 0' "fixed JIT victim clean"
has "$R/fixed-jit.out" 'deepest write: 0 bytes BELOW' "fixed JIT no escaped write"
has "$R/fixed-jit.out" 'aligned words holding a pointer into the subject buffer: 0' "fixed JIT no pointers"
expect_eq "fixed JIT exit code" "$(cat "$R/fixed-jit.rc")" "1"

has "$R/fixed-nojit.out" 'pcre2_match returned 2' "fixed interpreter match succeeds"
has "$R/fixed-nojit.out" 'victim bytes clobbered: 0' "fixed interpreter victim clean"
expect_eq "fixed interpreter exit code" "$(cat "$R/fixed-nojit.rc")" "0"

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
