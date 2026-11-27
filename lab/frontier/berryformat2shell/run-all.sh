#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUNS="$ROOT/runs"
mkdir -p "$RUNS"
exec > >(tee "$RUNS/run-all.out")
PASS=0
FAIL=0
RC=0

pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

run() {
    local label=$1
    shift
    set +e
    "$@" > "$RUNS/$label.out" 2>&1
    RC=$?
    set -e
}

expect_rc() {
    local label=$1 expected=$2
    if [[ $RC -eq $expected ]]; then pass "$label rc=$RC"; else fail "$label" "rc=$RC expected=$expected"; fi
}

expect_contains() {
    local label=$1 text=$2
    if grep -Fq -- "$text" "$RUNS/$label.out"; then pass "$label contains [$text]"; else fail "$label" "missing [$text]"; fi
}

expect_empty() {
    local label=$1
    if [[ ! -s $RUNS/$label.out ]]; then pass "$label empty output"; else fail "$label" "unexpected output"; fi
}
for bin in vuln-asan patched-asan upstream-fix-asan vuln-plain patched-plain vuln-hardened patched-hardened; do
    if [[ -x $ROOT/berry-$bin ]]; then pass "build $bin"; else fail "build $bin" "missing executable"; fi
done

run vuln-asan-format env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$ROOT/berry-vuln-asan" "$ROOT/inputs/format-overflow.be"
expect_rc vuln-asan-format 134
expect_contains vuln-asan-format 'AddressSanitizer: stack-buffer-overflow'
expect_contains vuln-asan-format 'WRITE of size 225'
expect_contains vuln-asan-format 'in get_mode src/be_strlib.c:542'

run patched-asan-format env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$ROOT/berry-patched-asan" "$ROOT/inputs/format-overflow.be"
expect_rc patched-asan-format 0
expect_empty patched-asan-format

for variant in vuln-asan patched-asan; do
    for input in format-safe.be format-numeric-safe.be; do
        label="$variant-$input"
        run "$label" env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
            "$ROOT/berry-$variant" "$ROOT/inputs/$input"
        expect_rc "$label" 0
        expect_empty "$label"
    done
done

run upstream-fix-asan-format env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$ROOT/berry-upstream-fix-asan" "$ROOT/inputs/format-overflow.be"
expect_rc upstream-fix-asan-format 0
expect_empty upstream-fix-asan-format

for input in format-safe.be format-numeric-safe.be lexer-safe.be; do
    label="upstream-fix-asan-$input"
    run "$label" env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
        "$ROOT/berry-upstream-fix-asan" "$ROOT/inputs/$input"
    expect_rc "$label" 0
    expect_empty "$label"
done

run upstream-fix-asan-lexer env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$ROOT/berry-upstream-fix-asan" "$ROOT/inputs/lexer-overflow.be"
expect_rc upstream-fix-asan-lexer 1
expect_contains upstream-fix-asan-lexer 'unfinished string'

run upstream-fix-asan-numeric-residual env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$ROOT/berry-upstream-fix-asan" "$ROOT/inputs/format-numeric-residual.be"
expect_rc upstream-fix-asan-numeric-residual 134
expect_contains upstream-fix-asan-numeric-residual 'AddressSanitizer: stack-buffer-overflow'
expect_contains upstream-fix-asan-numeric-residual 'WRITE of size 3'
expect_contains upstream-fix-asan-numeric-residual 'in mode_fixlen src/be_strlib.c:627'


run vuln-asan-lexer env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$ROOT/berry-vuln-asan" "$ROOT/inputs/lexer-overflow.be"
expect_rc vuln-asan-lexer 134
expect_contains vuln-asan-lexer 'AddressSanitizer: global-buffer-overflow'
expect_contains vuln-asan-lexer 'READ of size 1'
expect_contains vuln-asan-lexer '0 bytes after global variable'

run patched-asan-lexer env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$ROOT/berry-patched-asan" "$ROOT/inputs/lexer-overflow.be"
expect_rc patched-asan-lexer 1
expect_contains patched-asan-lexer 'unfinished string'

for variant in vuln-asan patched-asan; do
    label="$variant-lexer-safe.be"
    run "$label" env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
        "$ROOT/berry-$variant" "$ROOT/inputs/lexer-safe.be"
    expect_rc "$label" 0
    expect_empty "$label"
done

run patched-asan-numeric-residual env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$ROOT/berry-patched-asan" "$ROOT/inputs/format-numeric-residual.be"
expect_rc patched-asan-numeric-residual 134
expect_contains patched-asan-numeric-residual 'AddressSanitizer: stack-buffer-overflow'
expect_contains patched-asan-numeric-residual 'WRITE of size 3'
expect_contains patched-asan-numeric-residual 'in mode_fixlen src/be_strlib.c:561'

plain_ok=1
for i in 1 2 3 4 5; do
    label="vuln-plain-format-$i"
    run "$label" "$ROOT/berry-vuln-plain" "$ROOT/inputs/format-overflow.be"
    if [[ $RC -ne 139 ]]; then plain_ok=0; printf 'vuln-plain iteration %s rc=%s\n' "$i" "$RC"; fi
done
if [[ $plain_ok -eq 1 ]]; then pass 'vuln-plain format crashes 5/5 rc=139'; else fail 'vuln-plain format' 'not 5/5 rc=139'; fi

run patched-plain-format "$ROOT/berry-patched-plain" "$ROOT/inputs/format-overflow.be"
expect_rc patched-plain-format 0
expect_empty patched-plain-format

run vuln-hardened-format "$ROOT/berry-vuln-hardened" "$ROOT/inputs/format-overflow.be"
expect_rc vuln-hardened-format 134
expect_contains vuln-hardened-format 'buffer overflow detected'

run patched-hardened-format "$ROOT/berry-patched-hardened" "$ROOT/inputs/format-overflow.be"
expect_rc patched-hardened-format 0
expect_empty patched-hardened-format

run gdb-saved-rip gdb -q -batch -x "$ROOT/observe.gdb" --args "$ROOT/berry-vuln-plain"
expect_rc gdb-saved-rip 0
expect_contains gdb-saved-rip 'SAVED_RIP_BYTES=2b23302d2b23302d'
expect_contains gdb-saved-rip 'SAVED_RIP_VALUE=0x2d30232b2d30232b'

printf 'TOTAL: %s PASS / %s FAIL\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
