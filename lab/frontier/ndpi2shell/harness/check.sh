#!/bin/sh
# Deterministic assertions + normalized trace for ndpi2shell.
# 32 invocations (gcc/clang x vuln/fixed x plain/asan x 4 scenarios) plus two
# gdb chosen-byte probes. Trace excludes PID, addresses and absolute paths.
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

SCENARIOS='baseline escape utf8 nul'
for cc in gcc clang; do
    for v in vuln fixed; do
        for mode in plain asan; do
            for sc in $SCENARIOS; do
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

for cc in gcc clang; do
  for v in vuln fixed; do
    for mode in plain asan; do
      for sc in $SCENARIOS; do
        f="$OUT/$mode-$cc-$v-$sc.out"; tag="$mode-$cc-$v-$sc"
        # ASan faults before stdout flush in the vulnerable attack runs.
        if [ "$v" = vuln ] && [ "$mode" = asan ] && [ "$sc" != baseline ]; then
            :
        else
            expect "$f" "scenario=$sc" "$tag"
            expect "$f" "variant=$v" "$tag"
            expect "$f" 'dst_max_len=' "$tag"
        fi
        if [ "$sc" = baseline ]; then
            expect "$f" 'rc=5' "$tag"
            absent "$f" 'AddressSanitizer' "$tag"
            if [ "$mode" = plain ]; then
                expect "$f" 'tail=a5 a5 a5 a5 a5 a5 a5 a5' "$tag"
            fi
        elif [ "$v" = fixed ]; then
            expect "$f" 'rc=-1' "$tag"
            absent "$f" 'AddressSanitizer' "$tag"
            if [ "$mode" = plain ]; then
                expect "$f" 'tail=a5 a5 a5 a5 a5 a5 a5 a5' "$tag"
            fi
        elif [ "$mode" = asan ]; then
            expect "$f" 'ERROR: AddressSanitizer: heap-buffer-overflow' "$tag"
            expect "$f" 'WRITE of size 1' "$tag"
            case "$sc" in
                escape) expect "$f" 'ndpi_serializer.c.vuln:107' "$tag" ;;
                utf8)   expect "$f" 'ndpi_serializer.c.vuln:158' "$tag" ;;
                nul)    expect "$f" 'ndpi_serializer.c.vuln:163' "$tag" ;;
            esac
            expect "$f" 'EXIT=1' "$tag"
        else
            case "$sc" in
                escape) expect "$f" 'rc=10' "$tag"; expect "$f" 'tail=2f 22 a5 00' "$tag" ;;
                utf8)   expect "$f" 'rc=10' "$tag"; expect "$f" 'tail=80 22 a5 00' "$tag" ;;
                nul)    expect "$f" 'rc=8' "$tag";  expect "$f" 'tail=a5 00 a5 a5' "$tag" ;;
            esac
            absent "$f" 'AddressSanitizer' "$tag"
        fi
      done
    done
  done
done

# gdb: chosen byte and write index at the first out-of-bounds store (:107).
A="$OUT/gdb-chosen-jc.out"
set +e
gdb -q -batch -ex 'set pagination off' \
    -ex 'break ndpi_serializer.c.vuln:107' -ex 'run escape' \
    -ex 'printf "J=%d C=0x%02x\n", j, c' \
    "$HERE/gcc-vuln-plain" > "$A" 2>&1
set -e
expect "$A" 'J=8 C=0x2f' 'gdb-chosen-jc'

# gdb: chosen bytes in the caller's tail after the vulnerable call returns.
B="$OUT/gdb-chosen-tail.out"
set +e
gdb -q -batch -ex 'set pagination off' \
    -ex 'break ndpi_json_string_escape' -ex 'run escape' -ex 'finish' \
    -ex 'x/8xb dst+8' \
    "$HERE/gcc-vuln-plain" > "$B" 2>&1
set -e
expect "$B" '0x2f	0x22	0xa5	0x00' 'gdb-chosen-tail'

# Normalized trace: no PID, addresses or absolute paths.
TRACE="$OUT/trace.txt"
: > "$TRACE"
for cc in gcc clang; do
  for v in vuln fixed; do
    for mode in plain asan; do
      for sc in $SCENARIOS; do
        f="$OUT/$mode-$cc-$v-$sc.out"
        printf '%s ' "$mode-$cc-$v-$sc" >> "$TRACE"
        grep -E '^(scenario=|tail=|EXIT=)' "$f" | tr '\n' '|' >> "$TRACE"
        grep -oE '(ERROR: AddressSanitizer: heap-buffer-overflow|WRITE of size [0-9]+|ndpi_serializer\.c\.vuln:[0-9]+)' "$f" | tr '\n' '|' >> "$TRACE"
        printf '\n' >> "$TRACE"
      done
    done
  done
done
grep -E '^J=' "$A" >> "$TRACE"
grep -E '^0x[0-9a-f]{8,}:' "$B" | sed -E 's/^0x[0-9a-f]{8,}:[[:space:]]*/HEAP: /' | sed -E 's/0x[0-9a-f]{8,}/ADDR/g' >> "$TRACE"
HASH=$(sha256sum "$TRACE" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$HASH"
[ "$FAIL" -eq 0 ]
