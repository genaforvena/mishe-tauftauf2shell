#!/bin/sh
# Deterministic assertions + normalized trace for munt2shell.
# 24 invocations (gcc/clang x vuln/fixed x plain/asan x baseline/fragment/attack)
# plus one gdb chosen-byte probe. Trace excludes PID, addresses, paths, build ids.
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
    for cc in gcc clang; do
        for v in vuln fixed; do
            for mode in plain asan; do
                for sc in baseline fragment attack; do
                    f="$OUT/$mode-$cc-$v-$sc.out"
                    set +e
                    ASAN_OPTIONS=detect_leaks=0 "$HERE/$cc-$v-$mode" "$sc" > "$f" 2>&1
                    rc=$?
                    set -e
                    printf 'EXIT=%d\n' "$rc" >> "$f"
                done
            done
        done
    done
}
run_all

for cc in gcc clang; do
    for v in vuln fixed; do
        for mode in plain asan; do
            for sc in baseline fragment attack; do
                f="$OUT/$mode-$cc-$v-$sc.out"
                tag="$mode-$cc-$v-$sc"
                if [ "$sc" = attack ] && [ "$v" = vuln ] && [ "$mode" = asan ]; then
                    continue
                fi
                expect "$f" "scenario=$sc" "$tag"
                expect "$f" "variant=$v" "$tag"
                expect "$f" 'EXIT=0' "$tag"
                if [ "$sc" = baseline ]; then
                    expect "$f" 'sysex=1' "$tag"
                    expect "$f" 'lastlen=102' "$tag"
                    absent "$f" 'AddressSanitizer' "$tag"
                elif [ "$sc" = fragment ]; then
                    expect "$f" 'sysex=0' "$tag"
                    absent "$f" 'AddressSanitizer' "$tag"
                elif [ "$v" = vuln ] && [ "$mode" = plain ]; then
                    expect "$f" 'b32768=5a b32769=5a b32770=5a b32771=5a' "$tag"
                else # fixed attack
                    absent "$f" 'b32768=' "$tag"
                    absent "$f" 'AddressSanitizer' "$tag"
                fi
            done
        done
    done
done

# ASan vulnerable attack: the process aborts (EXIT=1) with a pinned WRITE.
for cc in gcc clang; do
    f="$OUT/asan-$cc-vuln-attack.out"
    expect "$f" 'ERROR: AddressSanitizer: heap-buffer-overflow' "asan-$cc-vuln-attack"
    expect "$f" 'WRITE of size 40001' "asan-$cc-vuln-attack"
    expect "$f" 'MidiStreamParser.cpp.vuln:250' "asan-$cc-vuln-attack"
    expect "$f" '0 bytes after 32768-byte region' "asan-$cc-vuln-attack"
    expect "$f" 'EXIT=1' "asan-$cc-vuln-attack"
done

# gdb chosen-byte probe: break in delete[] while the 32768-byte buffer is live.
G="$OUT/gdb-chosen.out"
set +e
gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'break operator delete[](void*)' \
    -ex 'ignore 1 1' \
    -ex 'run attack' \
    -ex 'print g_last_size' \
    -ex 'x/16xb g_last_alloc+32768' \
    -ex 'bt 4' \
    "$HERE/gcc-vuln-plain" > "$G" 2>&1
set -e
expect "$G" '$1 = 32768' 'gdb-chosen'
expect "$G" '0x5a' 'gdb-chosen'
expect "$G" 'MidiStreamParserImpl::~MidiStreamParserImpl' 'gdb-chosen'

TRACE="$OUT/trace.txt"
: > "$TRACE"
for cc in gcc clang; do
    for v in vuln fixed; do
        for mode in plain asan; do
            for sc in baseline fragment attack; do
                f="$OUT/$mode-$cc-$v-$sc.out"
                printf '%s ' "$mode-$cc-$v-$sc" >> "$TRACE"
                grep -E '^(scenario=|EXIT=)' "$f" | tr '\n' '|' >> "$TRACE"
                grep -oE '(ERROR: AddressSanitizer: heap-buffer-overflow|WRITE of size [0-9]+|MidiStreamParser\.cpp\.vuln:[0-9]+|0 bytes after [0-9]+-byte region)' "$f" | tr '\n' '|' >> "$TRACE"
                printf '\n' >> "$TRACE"
            done
        done
    done
done
grep -E '0x5a|\$1 = 32768' "$G" >> "$TRACE"
HASH=$(sha256sum "$TRACE" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$HASH"
[ "$FAIL" -eq 0 ]
