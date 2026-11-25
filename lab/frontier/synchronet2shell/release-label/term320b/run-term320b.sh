#!/usr/bin/env bash
# W19: shipped 3.20b puts link_list_t savedlines.first/.last inside the
# 64-byte TERM reach. Provisioning fetches raw release files (no network
# probes); every copy statement is extracted verbatim from answer.cpp.
set -uo pipefail
cd "$(dirname "$0")"
HERE=$PWD
EVID="$HERE/evidence"
mkdir -p "$EVID"
LOG="$EVID/evidence.log"
: > "$LOG"
pass=0; fail=0

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
check() {
    if [ "$2" = "$3" ]; then
        say "PASS $1"; pass=$((pass + 1))
    else
        say "FAIL $1 expected=[$2] actual=[$3]"; fail=$((fail + 1))
    fi
}
expect_pattern() { # name file pattern
    if grep -qF "$3" "$2"; then say "PASS $1"; pass=$((pass + 1))
    else say "FAIL $1 (missing $3 in $2)"; fail=$((fail + 1)); fi
}
expect_asan() { # name bin len want(overflow|clean)
    local out="$HERE/build/$1.out" rc
    "$HERE/build/$2" "$3" > "$out" 2>&1; rc=$?
    say "=== $1 (len=$3, want=$4) rc=$rc"
    sed -n '1,16p' "$out" | tee -a "$LOG"
    local ok=1
    if [ "$4" = overflow ]; then
        grep -q 'AddressSanitizer' "$out" || ok=0
        grep -q 'stack-buffer-overflow' "$out" || ok=0
        grep -q 'WRITE of size' "$out" || ok=0
        [ "$rc" -ne 0 ] || ok=0
    else
        [ "$rc" -eq 0 ] || ok=0
        ! grep -q 'AddressSanitizer' "$out" || ok=0
    fi
    if [ "$ok" -eq 1 ]; then say "PASS $1"; pass=$((pass+1))
    else say "FAIL $1"; fail=$((fail+1)); fi
}
expect_text() { # name bin len pattern
    local out="$HERE/build/$1.out" rc
    "$HERE/build/$2" "$3" > "$out" 2>&1; rc=$?
    say "=== $1 (len=$3) rc=$rc"
    cat "$out" | tee -a "$LOG"
    if [ "$rc" -eq 0 ] && grep -qF "$4" "$out"; then
        say "PASS $1"; pass=$((pass+1))
    else
        say "FAIL $1"; fail=$((fail+1))
    fi
}

SHA=db9c5d6fd37ef74b6e6ca647308d351e656de18d
BASE="https://raw.githubusercontent.com/SynchronetBBS/sbbs/$SHA"
fetch() { # url dest
    if sha256sum --check --status "$HERE/PINS.sha256" 2>/dev/null; then
        return 0
    fi
    curl -fsSL --max-time 60 -o "$2" "$1"
}
fetch "$BASE/src/sbbs3/answer.cpp"     "$EVID/answer-320b.cpp"
fetch "$BASE/src/sbbs3/sbbs.h"         "$EVID/sbbs-320b.h"
fetch "$BASE/src/sbbs3/telnet.h"       "$EVID/telnet-320b.h"
fetch "$BASE/src/sbbs3/sbbsdefs.h"     "$EVID/sbbsdefs-320b.h"
fetch "$BASE/src/xpdev/link_list.h"    "$EVID/link_list-320b.h"

say "run $(date -u +%FT%TZ) shipped-3.20b commit=$SHA"
sha256sum -c "$HERE/PINS.sha256" >> "$LOG" 2>&1
check "5 pinned 3.20b source hashes" "OK" \
  "$(sha256sum -c "$HERE/PINS.sha256" >/dev/null 2>&1 && echo OK || echo BAD)"
bash "$HERE/gen.sh" >> "$LOG" 2>&1 || { say "GEN_FAIL"; exit 2; }
say "gen: $(grep -c . "$HERE/vuln320b.inc") extracted lines"
check "verbatim getter line in extracted inc" 1 \
  "$(grep -cF 'cryptGetAttributeString(ssh_session, CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, terminal, &l)' "$HERE/vuln320b.inc")"
expect_pattern "shipped field order terminal/cterm_version/savedlines" \
  "$EVID/sbbs-320b.h" 'link_list_t savedlines{};'
expect_pattern "savedlines.first is first link_list_t member" \
  "$EVID/link_list-320b.h" 'list_node_t*		first;'

mkdir -p "$HERE/build"
build() {
    local cc="$1" out="$2"; shift 2
    "$cc" -std=c++17 -O0 -g -I"$HERE" "$@" "$HERE/answer320b_harness.cpp" -o "$HERE/build/$out"
}
build g++     vuln-asan-g++      -fsanitize=address -fno-omit-frame-pointer -DREDZONE_MODEL
build clang++ vuln-asan-clang    -fsanitize=address -fno-omit-frame-pointer -DREDZONE_MODEL
build g++     vuln-plain-g++
build clang++ vuln-plain-clang

expect_asan  asan-320b-g++-term64    vuln-asan-g++    64 overflow
expect_asan  asan-320b-clang-term64  vuln-asan-clang  64 overflow
expect_asan  asan-320b-g++-term40    vuln-asan-g++    40 clean
expect_text  plain-320b-g++-term64   vuln-plain-g++   64 PTR_CONTROL_OK
expect_text  plain-320b-clang-term64 vuln-plain-clang 64 PTR_CONTROL_OK
expect_text  plain-320b-g++-term40   vuln-plain-g++   40 SHORT_CONTROL_OK


say "RESULT $pass PASS / $fail FAIL"
say "source-bound harness only: no 3.20b build, no wire, no dereference of the chosen pointers, no rung/witness change"
sha256sum "$LOG" > "$EVID/evidence.sha256"
cat "$EVID/evidence.sha256"
[ "$fail" -eq 0 ]
