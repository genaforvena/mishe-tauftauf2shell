#!/usr/bin/env bash
# CVE-2026-6679 reproducible harness: vulnerable v5.9.0 vs fixed v5.9.1.
# All activity is local; no sockets, listeners, or off-loopback traffic.
set -uo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$#" -ne 1 ]; then
    echo "usage: run.sh <absolute-outdir>" >&2
    exit 2
fi
OUT="$1"
case "$OUT" in
    /*) ;;
    *) echo "outdir must be absolute: $OUT" >&2; exit 2 ;;
esac

mkdir -p "$OUT/logs" "$OUT/.state"
: > "$OUT/trace.txt"
: > "$OUT/trace.fail"
FAILED=0

pass() { printf 'PASS %s\n' "$1" | tee -a "$OUT/trace.txt"; }
fail() {
    printf 'FAIL %s\n' "$1" | tee -a "$OUT/trace.fail" >&2
    FAILED=$((FAILED + 1))
}
has() { grep -qF -- "$1" "$2"; }

# 1. Pinned artifact verification (also repeated inside build.sh).
if (cd "$LAB/src" && sha256sum -c SHA256SUMS > "$OUT/logs/sha256sum-check.log" 2>&1); then
    pass pins_sha256_verified
else
    fail pins_sha256_verified
fi

# 2. Build both pinned versions and the harness against each real library.
if bash "$LAB/build.sh" "$OUT" > "$OUT/logs/build.log" 2>&1; then
    :
else
    cat "$OUT/logs/build.log" >&2
    fail build_both_pins
fi
for tok in build_v5.9.0_asan build_v5.9.1_asan; do
    if has "PASS $tok" "$OUT/logs/build.log"; then pass "$tok"; else fail "$tok"; fi
done
for ver in 5.9.0 5.9.1; do
    if grep -q '^#define WOLFSSL_DTLS13' \
        "$LAB/build/wolfssl-${ver}-stable/wolfssl/options.h"; then
        pass "dtls13_option_v${ver}"
    else
        fail "dtls13_option_v${ver}"
    fi
done

ASAN="symbolize=1:detect_leaks=0:abort_on_error=0"

# 3. Vulnerable build: expect word16 truncation and an ASan WRITE at the sink.
if [ -x "$OUT/ack_overflow_v5.9.0" ]; then
    ASAN_OPTIONS="$ASAN" "$OUT/ack_overflow_v5.9.0" 4097 DEFAULT \
        > "$OUT/logs/vuln.stdout" 2> "$OUT/logs/vuln.asan"
    vrc=$?
else
    vrc=99
fi
echo "vulnerable_harness_rc=$vrc" > "$OUT/logs/vuln.rc"
if has 'FACT list_count=4097' "$OUT/logs/vuln.stdout"; then
    pass vuln_list_4097
else
    fail vuln_list_4097
fi
if has 'FACT word16_length=16' "$OUT/logs/vuln.stdout" &&
   has 'FACT exact_length=65552' "$OUT/logs/vuln.stdout" &&
   has 'FACT truncation=YES' "$OUT/logs/vuln.stdout"; then
    pass vuln_word16_truncation_16_of_65552
else
    fail vuln_word16_truncation_16_of_65552
fi
if has 'ERROR: AddressSanitizer: heap-buffer-overflow' "$OUT/logs/vuln.asan" &&
   has 'WRITE of size 8' "$OUT/logs/vuln.asan" &&
   has '31-byte region' "$OUT/logs/vuln.asan"; then
    pass vuln_asan_heap_buffer_overflow_WRITE
else
    fail vuln_asan_heap_buffer_overflow_WRITE
fi
if has 'c64toa' "$OUT/logs/vuln.asan" &&
   has 'Dtls13WriteAckMessage' "$OUT/logs/vuln.asan" &&
   grep -qE 'src/dtls13\.c:26[0-9][0-9]' "$OUT/logs/vuln.asan"; then
    pass vuln_sink_c64toa_in_Dtls13WriteAckMessage
else
    fail vuln_sink_c64toa_in_Dtls13WriteAckMessage
fi

# 4. Fixed build control: same 4097 inserts, list capped, no ASan findings.
if [ -x "$OUT/ack_overflow_v5.9.1" ]; then
    ASAN_OPTIONS="$ASAN" "$OUT/ack_overflow_v5.9.1" 4097 DEFAULT \
        > "$OUT/logs/fixed.stdout" 2> "$OUT/logs/fixed.asan"
    frc=$?
else
    frc=99
fi
echo "fixed_harness_rc=$frc" > "$OUT/logs/fixed.rc"
if has 'FACT list_count=128' "$OUT/logs/fixed.stdout"; then
    pass fixed_list_capped_128
else
    fail fixed_list_capped_128
fi
if has 'FACT word16_length=2048' "$OUT/logs/fixed.stdout" &&
   has 'FACT exact_length=2048' "$OUT/logs/fixed.stdout" &&
   has 'FACT truncation=NO' "$OUT/logs/fixed.stdout"; then
    pass fixed_no_word16_truncation
else
    fail fixed_no_word16_truncation
fi
if [ "$frc" -eq 0 ] &&
   has 'FACT write_ret=0' "$OUT/logs/fixed.stdout" &&
   has 'FACT returned_length=2050' "$OUT/logs/fixed.stdout" &&
   has 'FACT harness_ok=YES' "$OUT/logs/fixed.stdout"; then
    pass fixed_write_ok_length_2050
else
    fail fixed_write_ok_length_2050
fi
if [ ! -s "$OUT/logs/fixed.asan" ] &&
   ! has 'AddressSanitizer' "$OUT/logs/fixed.asan"; then
    pass fixed_asan_clean
else
    fail fixed_asan_clean
fi

# 5. Stable trace hash over the ordered PASS lines only.
hash="$(sha256sum "$OUT/trace.txt" | awk '{print $1}')"
printf '%s  trace.txt\n' "$hash" > "$OUT/TRACE.sha256"
printf 'TRACE_HASH %s\n' "$hash"
printf 'RESULT pass=%d fail=%d\n' "$(wc -l < "$OUT/trace.txt")" "$FAILED"

[ "$FAILED" -eq 0 ]
