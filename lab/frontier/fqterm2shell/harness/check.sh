#!/bin/sh
# Deterministic assertions + normalized trace for fqterm2shell.
# 16 invocations (g++/clang++ x vuln/fixed x plain/asan x baseline/oob-chosen),
# plus 1 gdb chosen-byte probe. Trace excludes PID, addresses, paths, build ids.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0
FAIL=0

expect() { # file expected-substring label
    if grep -qF -- "$2" "$1"; then PASS=$((PASS+1))
    else FAIL=$((FAIL+1)); printf 'FAIL %s: missing %s\n' "$3" "$2"; fi
}
absent() { # file forbidden-substring label
    if grep -qF -- "$2" "$1"; then FAIL=$((FAIL+1)); printf 'FAIL %s: unexpected %s\n' "$3" "$2"
    else PASS=$((PASS+1)); fi
}

run_all() {
    for cc in g++ clang++; do
        for v in vuln fixed; do
            for mode in plain asan; do
                for sc in baseline oob-chosen; do
                    f="$OUT/$mode-$cc-$v-$sc.out"
                    set +e
                    "$HERE/bin-$cc-$v-$mode" "$sc" > "$f" 2>&1
                    rc=$?
                    set -e
                    printf 'EXIT=%d\n' "$rc" >> "$f"
                done
            done
        done
    done
}
run_all

for cc in g++ clang++; do
    for v in vuln fixed; do
        for mode in plain asan; do
            for sc in baseline oob-chosen; do
                f="$OUT/$mode-$cc-$v-$sc.out"
                tag="$mode-$cc-$v-$sc"
                if [ "$sc" = baseline ]; then
                    expect "$f" 'rc=0 scenario=baseline paramIndex=2 p0=1 p29=0' "$tag"
                    expect "$f" 'EXIT=0' "$tag"
                    expect "$f" 'sizeof_obj=280 off_param=60 off_end=280' "$tag"
                    absent "$f" 'AddressSanitizer' "$tag"
                elif [ "$v" = vuln ] && [ "$mode" = asan ]; then
                    expect "$f" 'ERROR: AddressSanitizer: heap-buffer-overflow' "$tag"
                    expect "$f" 'READ of size 4' "$tag"
                    expect "$f" 'fqterm_decode.cpp.vuln:694' "$tag"
                    expect "$f" '0 bytes after 280-byte region' "$tag"
                    expect "$f" 'EXIT=1' "$tag"
                elif [ "$v" = vuln ] && [ "$mode" = plain ]; then
                    expect "$f" 'rc=0 scenario=oob-chosen paramIndex=59 p0=9 p29=9' "$tag"
                    expect "$f" 'slot35=5a5a5a5a' "$tag"
                    expect "$f" 'canary: 09 00 00 00 09 00 00 00 09 00 00 00 09 00 00 00' "$tag"
                    expect "$f" 'EXIT=0' "$tag"
                else # fixed, oob-chosen, both modes
                    expect "$f" 'rc=0 scenario=oob-chosen paramIndex=29 p0=9' "$tag"
                    if [ "$mode" = plain ]; then
                        expect "$f" 'slot35=00000000' "$tag"
                        expect "$f" 'canary: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' "$tag"
                    fi
                    absent "$f" 'AddressSanitizer' "$tag"
                    absent "$f" 'LeakSanitizer' "$tag"
                    expect "$f" 'EXIT=0' "$tag"
                fi
            done
        done
    done
done

# gdb chosen-byte probe: break at operator delete, inspect the still-live object
# from main's frame. Plain vulnerable build; 0x5a5a5a5a is a chosen 32-bit value.
G="$OUT/gdb-chosen.out"
set +e
gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'break operator delete(void*)' \
    -ex 'run oob-chosen' \
    -ex 'frame 1' \
    -ex 'print/x d.param_[35]' \
    -ex 'x/16xb o.canary' \
    "$HERE/bin-g++-vuln-plain" > "$G" 2>&1
set -e
expect "$G" '0x5a5a5a5a' 'gdb-chosen'
expect "$G" '0x09' 'gdb-chosen'
expect "$G" 'in main' 'gdb-chosen'

TRACE="$OUT/trace.txt"
: > "$TRACE"
for cc in g++ clang++; do
    for v in vuln fixed; do
        for mode in plain asan; do
            for sc in baseline oob-chosen; do
                f="$OUT/$mode-$cc-$v-$sc.out"
                printf '%s ' "$mode-$cc-$v-$sc" >> "$TRACE"
                grep -E '^(rc=|sizeof_obj=|slot35=|canary:|EXIT=)' "$f" | tr '\n' '|' >> "$TRACE"
                grep -oE '(ERROR: AddressSanitizer: heap-buffer-overflow|READ of size 4|fqterm_decode\.cpp\.vuln:694|0 bytes after 280-byte region)' "$f" | tr '\n' '|' >> "$TRACE"
                printf '\n' >> "$TRACE"
            done
        done
    done
done
grep -E '0x5a5a5a5a|0x09.*0x09' "$G" >> "$TRACE"
HASH=$(sha256sum "$TRACE" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$HASH"
[ "$FAIL" -eq 0 ]
