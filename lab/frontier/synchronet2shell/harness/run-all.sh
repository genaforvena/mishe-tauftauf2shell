#!/usr/bin/env bash
# Rebuild from pinned sources and run the measured matrix. Loopback/local only.
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
LOG=evidence.log
: > "$LOG"
pass=0; fail=0

say() { printf '%s\n' "$*" | tee -a "$LOG"; }

build() {
    local out="$1" cc="$2"; shift 2
    "$cc" -std=c++17 -O0 -g -Iharness "$@" harness/answer_harness.cpp -o "build/$out"
}

check_asan() {
    local name="$1" bin="$2" len="$3" want="$4"
    local out="build/$name.out"; local rc
    "build/$bin" "$len" >"$out" 2>&1; rc=$?
    say "=== $name (len=$len, want=$want) rc=$rc"
    sed -n '1,22p' "$out" | tee -a "$LOG"
    local ok=1
    if [ "$want" = overflow ]; then
        grep -q 'AddressSanitizer' "$out" || ok=0
        grep -q 'stack-buffer-overflow' "$out" || ok=0
        grep -q 'WRITE of size' "$out" || ok=0
        [ "$rc" -ne 0 ] || ok=0
    else
        [ "$rc" -eq 0 ] || ok=0
        ! grep -q 'AddressSanitizer' "$out" || ok=0
    fi
    if [ "$ok" -eq 1 ]; then say "PASS $name"; pass=$((pass+1)); else say "FAIL $name"; fail=$((fail+1)); fi
}

check_text() {
    local name="$1" bin="$2" len="$3" text="$4"
    local out="build/$name.out"; local rc
    "build/$bin" "$len" >"$out" 2>&1; rc=$?
    say "=== $name (len=$len, want=$text) rc=$rc"
    cat "$out" | tee -a "$LOG"
    local ok=1
    [ "$rc" -eq 0 ] || ok=0
    grep -q "$text" "$out" || ok=0
    if [ "$ok" -eq 1 ]; then say "PASS $name"; pass=$((pass+1)); else say "FAIL $name"; fail=$((fail+1)); fi
}

say "$(date -u +%FT%TZ) sha256 of pins:"
sha256sum -c PINS.sha256 >>"$LOG" 2>&1 || { say "PIN_CHECK_FAIL"; exit 1; }
cat PINS.sha256 >>"$LOG"
bash harness/gen.sh >>"$LOG" 2>&1

say "Build ids: $(g++ --version | sed -n '1p') | $(clang++ --version | sed -n '1p')"
build vuln-asan-g++   g++     -fsanitize=address -fno-omit-frame-pointer -DREDZONE_MODEL
build vuln-asan-clang clang++ -fsanitize=address -fno-omit-frame-pointer -DREDZONE_MODEL
build fixed-asan-g++   g++     -fsanitize=address -fno-omit-frame-pointer -DFIXED
build fixed-asan-clang clang++ -fsanitize=address -fno-omit-frame-pointer -DFIXED
build vuln-plain-g++   g++
build vuln-plain-clang clang++
build fixed-plain-g++  g++     -DFIXED

check_asan   asan-vuln-g++-term64      vuln-asan-g++    64 overflow
check_asan   asan-vuln-clang-term64    vuln-asan-clang  64 overflow
check_asan   asan-vuln-g++-term40      vuln-asan-g++    40 clean
check_asan   asan-fixed-g++-term64     fixed-asan-g++   64 clean
check_asan   asan-fixed-clang-term64   fixed-asan-clang 64 clean
check_text   plain-vuln-g++-term64     vuln-plain-g++   64 CHOSEN_BYTES_OK
check_text   plain-vuln-clang-term64   vuln-plain-clang 64 CHOSEN_BYTES_OK
check_text   plain-vuln-g++-term40     vuln-plain-g++   40 SHORT_CONTROL_OK
check_text   plain-fixed-g++-term64    fixed-plain-g++  64 FIXED_CONTROL_OK

say "RESULT $pass PASS / $fail FAIL"
sha256sum "$LOG" > evidence.sha256
cat evidence.sha256
[ "$fail" -eq 0 ]
