#!/usr/bin/env bash
# Chosen-byte harness: verbatim pinned validator + eval_args, minimal stubs.
set -u
cd "$(dirname "$0")"
H=$(pwd)
FAIL=0

gen() { python3 "$H/gen.py" "$1" > "$H/fn.inc"; }

build() {
    local cc="$1" mode="$2" out="$3"
    if [ "$mode" = asan ]; then
        "$cc" -g -O0 -fsanitize=address -o "$out" "$H/harness.c"
    else
        "$cc" -g -O0 -o "$out" "$H/harness.c"
    fi
}

check() {
    local name="$1" expected="$2" actual="$3"
    local line
    line=$(printf '%s' "$actual" | grep -E "$expected" | head -1)
    if [ -n "$line" ]; then
        echo "PASS $name :: $line"
    else
        echo "FAIL $name :: expected /$expected/ in: $actual"
        FAIL=$((FAIL + 1))
    fi
}

gen vuln
build gcc plain v-plain
build gcc asan v-asan
build clang asan v-clang-asan

gen fixed
build gcc plain f-plain
build gcc asan f-asan

echo "=== vuln gcc plain, chosen base 0x41 ==="
O=$(./v-plain 12 0x41 2>&1); echo "$O"
check vuln_validator 'validator_bogus=0' "$O"
check vuln_chosen_A 'cmdline=AAAAAAAA' "$O"

echo "=== vuln gcc plain, chosen base 0x5a ==="
O=$(./v-plain 12 0x5a 2>&1); echo "$O"
check vuln_chosen_Z 'cmdline=ZZZZZZZZ' "$O"

echo "=== fixed gcc plain, same packet ==="
O=$(./f-plain 12 0x41 2>&1); echo "$O"
check fixed_rejects 'validator_bogus=1' "$O"
check fixed_no_copy 'cmdline_len=0 cmdline=$' "$O"

echo "=== vuln gcc ASan, chosen base 0x5a ==="
O=$(ASAN_OPTIONS=detect_leaks=0 ./v-asan 12 0x5a 2>&1); echo "$O"
check asan_chosen 'cmdline=ZZZZZZZZ' "$O"

echo "=== fixed gcc ASan, same packet ==="
O=$(ASAN_OPTIONS=detect_leaks=0 ./f-asan 12 0x5a 2>&1); echo "$O"
check fixed_asan_clean 'cmdline_len=0 cmdline=$' "$O"

echo "=== vuln clang ASan, chosen base 0x5a ==="
O=$(ASAN_OPTIONS=detect_leaks=0 ./v-clang-asan 12 0x5a 2>&1); echo "$O"
check clang_chosen 'cmdline=ZZZZZZZZ' "$O"

echo "=== vuln gcc ASan, 40-byte oversized copy into 15-byte cmdline ==="
O=$(ASAN_OPTIONS=detect_leaks=0 ./v-asan 40 0x5a 2>&1); echo "$O" | head -12
check stack_overflow 'stack-buffer-overflow' "$O"

echo "FAILURES=$FAIL"
exit "$FAIL"
