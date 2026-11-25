#!/usr/bin/env bash
set -uo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p evidence
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
    bash bootstrap.sh > evidence/bootstrap.log 2>&1 || { cat evidence/bootstrap.log; exit 1; }
fi
pass=0
fail=0
check() {
    local name=$1 want=$2 pattern=$3; shift 3
    local out="evidence/$name.out" rc
    if "$@" >"$out" 2>&1; then rc=0; else rc=$?; fi
    if [[ $rc == "$want" ]] && grep -Fq -- "$pattern" "$out"; then
        printf 'PASS %s rc=%s\n' "$name" "$rc"; pass=$((pass+1))
    else
        printf 'FAIL %s rc=%s want=%s missing=%s\n' "$name" "$rc" "$want" "$pattern"
        fail=$((fail+1))
    fi
}
check pins 0 'OK' bash -c 'cd pins && sha256sum -c SHA256SUMS'
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
check vuln-asan-attack 134 'WRITE of size 4' harness/vuln-asan attack
check fixed-asan-attack 0 'PAGES=3' harness/fixed-asan attack
check vuln-asan-safe 0 'PAGES=3' harness/vuln-asan safe
check fixed-asan-safe 0 'PAGES=3' harness/fixed-asan safe
for n in 1 2 3; do
    check "vuln-plain-chosen-$n" 139 'PAST_PIXELS=554154ff554154ff554154ff' \
        env READ_PAST=1 harness/vuln-plain chosen
done
check fixed-asan-chosen 0 'PAGES=3' harness/fixed-asan chosen
printf 'RESULT %d PASS / %d FAIL\n' "$pass" "$fail" | tee evidence/summary.txt
[[ $fail == 0 ]]
