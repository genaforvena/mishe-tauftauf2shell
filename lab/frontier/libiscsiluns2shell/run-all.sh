#!/usr/bin/env bash
# Reproduce the pinned REPORT LUNS heap WRITE-4 and its fixed/safe controls.
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$ROOT/runs"
PASS=0
FAIL=0

check() {
    local name=$1 expr=$2
    if eval "$expr"; then
        printf 'PASS %s\n' "$name"; PASS=$((PASS+1))
    else
        printf 'FAIL %s\n' "$name"; FAIL=$((FAIL+1))
    fi
}

for variant in vuln fixed; do
    for mode in asan plain; do
        flags='-O0 -g'
        [[ $mode == asan ]] && flags="$flags -fsanitize=address"
        gcc $flags -I "$ROOT/src-$variant-$mode/include" \
            -I "$ROOT/src-$variant-$mode" \
            "$ROOT/harness/reportluns.c" \
            "$ROOT/src-$variant-$mode/lib/.libs/libiscsi.a" \
            -lgnutls -o "$ROOT/harness/$variant-$mode" \
            > "$ROOT/runs/compile-$variant-$mode.log" 2>&1
        printf 'COMPILE %s-%s rc=%d\n' "$variant" "$mode" "$?"
    done
done

run() {
    local variant=$1 mode=$2 n=$3 out="$ROOT/runs/$variant-$mode-$n.out"
    ASAN_OPTIONS=detect_leaks=0 "$ROOT/harness/$variant-$mode" "$n" \
        > "$out" 2>&1
    printf '%d' "$?" > "$out.rc"
}

for variant in vuln fixed; do
    for mode in asan plain; do
        for n in 4 8 16; do run "$variant" "$mode" "$n"; done
    done
done

f() { cat "$ROOT/runs/$1.out"; }
r() { cat "$ROOT/runs/$1.out.rc"; }

check 'vuln-asan-n4-rc'            "[[ \$(r vuln-asan-4) == 1 ]]"
check 'vuln-asan-n4-asan-header'  "f vuln-asan-4 | grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow'"
check 'vuln-asan-n4-write4'       "f vuln-asan-4 | grep -q 'WRITE of size 4'"
check 'vuln-asan-n4-sink-line'    "f vuln-asan-4 | grep -q 'scsi-lowlevel.c:590'"
check 'vuln-asan-n4-10byte-region' "f vuln-asan-4 | grep -q '0 bytes after 10-byte region'"
check 'vuln-plain-n4-num-minus1'  "f vuln-plain-4 | grep -q 'num=4294967295 (-1)'"
check 'vuln-asan-n8-clean'        "[[ \$(r vuln-asan-8) == 0 ]] && ! f vuln-asan-8 | grep -q AddressSanitizer"
check 'vuln-asan-n16-clean'       "[[ \$(r vuln-asan-16) == 0 ]] && ! f vuln-asan-16 | grep -q AddressSanitizer"
check 'fixed-asan-n4-null'        "[[ \$(r fixed-asan-4) == 0 ]] && f fixed-asan-4 | grep -q 'unmarshall=(nil)'"
check 'fixed-plain-n4-null'       "[[ \$(r fixed-plain-4) == 0 ]] && f fixed-plain-4 | grep -q 'unmarshall=(nil)'"
check 'fixed-asan-n8-clean'       "[[ \$(r fixed-asan-8) == 0 ]] && f fixed-asan-8 | grep -q 'num=0 (0)'"
check 'fixed-plain-n16-clean'     "[[ \$(r fixed-plain-16) == 0 ]] && f fixed-plain-16 | grep -q 'num=1 (1)'"

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
