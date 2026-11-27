#!/usr/bin/env bash
# Evidence runner: tcpprep --services parse_services() stack write (GHSA-fwcr-mqg6-hqmx).
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
RUNS="$ROOT/runs"
mkdir -p "$RUNS"
pass=0
fail=0

expect() {
    local name=$1 pattern=$2; shift 2
    local out="$RUNS/$name.out"
    "$@" > "$out" 2>&1
    local rc=$?
    if grep -qF -- "$pattern" "$out"; then
        printf 'PASS %s (rc=%d, found %s)\n' "$name" "$rc" "$pattern"
        pass=$((pass + 1))
    else
        printf 'FAIL %s (rc=%d, missing %s)\n' "$name" "$rc" "$pattern"
        fail=$((fail + 1))
    fi
}

reject() {
    local name=$1 pattern=$2; shift 2
    local out="$RUNS/$name.out"
    "$@" > "$out" 2>&1
    local rc=$?
    if grep -qF -- "$pattern" "$out"; then
        printf 'FAIL %s (rc=%d, unexpected %s)\n' "$name" "$rc" "$pattern"
        fail=$((fail + 1))
    else
        printf 'PASS %s (rc=%d, absent %s)\n' "$name" "$rc" "$pattern"
        pass=$((pass + 1))
    fi
}

run_tcpprep() {
    local variant=$1 mode=$2 input=$3
    (cd "$ROOT/src-$variant" && "$ROOT/build-$variant-$mode/src/tcpprep" \
        --services="$ROOT/inputs/$input.services" --port \
        -i test/test.pcap -o "$RUNS/$variant-$mode-$input.cache")
}

# Pinned bytes.
(cd "$ROOT" && sha256sum -c HARNESS_SHA256.txt) > "$RUNS/hashes.out" 2>&1
if grep -qF 'FAILED' "$RUNS/hashes.out"; then
    cat "$RUNS/hashes.out"
    printf 'FAIL pinned hashes\n'
    fail=$((fail + 1))
else
    printf 'PASS pinned hashes (%d entries)\n' "$(wc -l < "$RUNS/hashes.out")"
    pass=$((pass + 1))
fi

# Vulnerable: direct ASan redzone write past port[10] at services.c:74.
expect vuln-asan-20 'WRITE of size 20' run_tcpprep vuln asan digits20
expect vuln-asan-20-sink 'src/common/services.c:74' cat "$RUNS/vuln-asan-20.out"
expect vuln-asan-20-frame 'Memory access at offset 202 overflows this variable' \
    cat "$RUNS/vuln-asan-20.out"
reject vuln-asan-20-overlap 'strncpy-param-overlap' cat "$RUNS/vuln-asan-20.out"
expect vuln-asan-11 'WRITE of size 11' run_tcpprep vuln asan digits11

# Fixed: each copy is clamped to sizeof(port)-1 / sizeof(proto)-1.
reject fixed-asan-20 'AddressSanitizer' run_tcpprep fixed asan digits20
reject fixed-asan-11 'AddressSanitizer' run_tcpprep fixed asan digits11

# Safe inputs on both pinned trees.
reject vuln-asan-safe5 'AddressSanitizer' run_tcpprep vuln asan safe5
reject fixed-asan-safe5 'AddressSanitizer' run_tcpprep fixed asan safe5
reject vuln-asan-safe9 'AddressSanitizer' run_tcpprep vuln asan safe9
reject fixed-asan-safe9 'AddressSanitizer' run_tcpprep fixed asan safe9

printf 'TOTAL: %d PASS / %d FAIL\n' "$pass" "$fail"
test "$fail" -eq 0
