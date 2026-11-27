#!/usr/bin/env bash
# Evidence runner for the coturn OAuth nonce stack write (CVE-2026-43994).
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

# Pinned inputs and harness bytes.
(cd "$ROOT" && sha256sum -c HARNESS_SHA256.txt) > "$RUNS/hashes.out" 2>&1
if grep -qF 'FAILED' "$RUNS/hashes.out"; then
    cat "$RUNS/hashes.out"
    printf 'FAIL pinned hashes\n'
    fail=$((fail + 1))
else
    printf 'PASS pinned hashes (%d entries)\n' "$(wc -l < "$RUNS/hashes.out")"
    pass=$((pass + 1))
fi

expect vuln-asan-990 'WRITE of size 990' \
    "$ROOT/coturn-vuln-asan" "$ROOT/inputs/nonce-990.bin"
expect vuln-asan-990-sink 'decode_oauth_token_gcm' cat "$RUNS/vuln-asan-990.out"
expect fixed-asan-990 'nonce length too large: 990 > 256' \
    "$ROOT/coturn-fixed-asan" "$ROOT/inputs/nonce-990.bin"
reject fixed-asan-990-no-asan 'AddressSanitizer' cat "$RUNS/fixed-asan-990.out"

expect vuln-asan-safe256 'DECODE_OK=0 NONCE_LEN=256' \
    "$ROOT/coturn-vuln-asan" "$ROOT/inputs/nonce-256-safe.bin"
reject vuln-asan-safe256-no-asan 'stack-buffer-overflow' cat "$RUNS/vuln-asan-safe256.out"
expect fixed-asan-safe256 'DECODE_OK=0 NONCE_LEN=256' \
    "$ROOT/coturn-fixed-asan" "$ROOT/inputs/nonce-256-safe.bin"
expect vuln-asan-safe16 'DECODE_OK=0 NONCE_LEN=16' \
    "$ROOT/coturn-vuln-asan" "$ROOT/inputs/nonce-16-safe.bin"
expect fixed-asan-safe16 'DECODE_OK=0 NONCE_LEN=16' \
    "$ROOT/coturn-fixed-asan" "$ROOT/inputs/nonce-16-safe.bin"

expect vuln-plain-990-chosen 'timestamp=0x4141414141414141' \
    "$ROOT/coturn-vuln-plain" "$ROOT/inputs/nonce-990.bin"
expect vuln-plain-990-key-length 'key_length=0x4141' \
    cat "$RUNS/vuln-plain-990-chosen.out"
expect fixed-plain-990-clean 'timestamp=0x0000000000000000' \
    "$ROOT/coturn-fixed-plain" "$ROOT/inputs/nonce-990.bin"

printf 'TOTAL: %d PASS / %d FAIL\n' "$pass" "$fail"
test "$fail" -eq 0
