#!/bin/sh
# Reproduce CVE-2026-70659 on the verbatim shipped imatrix.cpp at tags
# master-742-1a13107 (vulnerable) and master-763-4fcc6fe (fixed).
# Stub headers supply only the GGML type surface; the loader sink is unmodified.
# Run from this directory. Raw output and rc files go to runs/.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p runs evidence

python3 harness/make_inputs.py 64 > runs/inputs.log || exit 1

for pin in vuln fixed; do
    for mode in asan plain; do
        flags="-std=c++17 -O0 -g -fno-omit-frame-pointer -I harness/stubs"
        if [ "$mode" = asan ]; then flags="$flags -fsanitize=address"; fi
        # shellcheck disable=SC2086
        g++ -x c++ $flags "src/imatrix.cpp.$pin" harness/main.cpp \
            -o "runs/$mode-$pin" || exit 1
    done
done

run_case() {
    name=$1
    bin=$2
    input=$3
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
        "./runs/$bin" "evidence/$input.imatrix" > "runs/$name.out" 2>&1
    printf '%s\n' "$?" > "runs/$name.rc"
}

run_case asan-vuln-attack asan-vuln attack
run_case asan-fixed-attack asan-fixed attack
run_case asan-vuln-safe asan-vuln safe
run_case asan-fixed-safe asan-fixed safe
run_case plain-vuln-attack plain-vuln attack
run_case plain-vuln-safe plain-vuln safe
run_case plain-fixed-attack plain-fixed attack
run_case plain-fixed-safe plain-fixed safe

pass=0
fail=0
check() {
    label=$1
    expected=$2
    got=$3
    if [ "$got" = "$expected" ]; then
        printf 'PASS %s: %s\n' "$label" "$got"
        pass=$((pass + 1))
    else
        printf 'FAIL %s: expected %s got %s\n' "$label" "$expected" "$got"
        fail=$((fail + 1))
    fi
}

check "asan-vuln-overflow" yes \
    "$(grep -q 'AddressSanitizer: heap-buffer-overflow' runs/asan-vuln-attack.out && echo yes || echo no)"
check "asan-vuln-sink" yes \
    "$(grep -q 'imatrix.cpp.vuln:302 in IMatrixCollector::load_imatrix' runs/asan-vuln-attack.out && echo yes || echo no)"
check "asan-vuln-allocation-site" yes \
    "$(grep -q 'imatrix.cpp.vuln:288' runs/asan-vuln-attack.out && echo yes || echo no)"
check "asan-vuln-4-byte-region" yes \
    "$(grep -q '0 bytes after 4-byte region' runs/asan-vuln-attack.out && echo yes || echo no)"
check "asan-vuln-rc" 1 "$(cat runs/asan-vuln-attack.rc)"
check "asan-fixed-rejects" yes \
    "$(grep -q 'inconsistent size for a repeated entry (1 vs 64)' runs/asan-fixed-attack.out && echo yes || echo no)"
check "asan-fixed-no-asan" no \
    "$(grep -q 'AddressSanitizer' runs/asan-fixed-attack.out && echo yes || echo no)"
check "asan-fixed-rc" 3 "$(cat runs/asan-fixed-attack.rc)"
check "asan-vuln-safe-clean" no \
    "$(grep -q 'AddressSanitizer' runs/asan-vuln-safe.out && echo yes || echo no)"
check "asan-vuln-safe-rc" 0 "$(cat runs/asan-vuln-safe.rc)"
check "asan-fixed-safe-clean" no \
    "$(grep -q 'AddressSanitizer' runs/asan-fixed-safe.out && echo yes || echo no)"
check "asan-fixed-safe-rc" 0 "$(cat runs/asan-fixed-safe.rc)"
check "plain-vuln-crash-diagnostic" yes \
    "$(grep -q 'double free or corruption (out)' runs/plain-vuln-attack.out && echo yes || echo no)"
check "plain-vuln-rc-sigabrt" 134 "$(cat runs/plain-vuln-attack.rc)"
check "plain-vuln-safe-rc" 0 "$(cat runs/plain-vuln-safe.rc)"
check "plain-fixed-attack-reject-rc" 3 "$(cat runs/plain-fixed-attack.rc)"
check "plain-fixed-safe-rc" 0 "$(cat runs/plain-fixed-safe.rc)"

printf 'NOTE: ASan traps on the OOB READ half of e.values[i] += tmp[i];\n'
printf 'the OOB WRITE half and the e.counts[i] write are not separately observed.\n'
printf 'RESULT PASS=%d FAIL=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
