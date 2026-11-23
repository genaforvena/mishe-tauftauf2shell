#!/bin/sh
# Deterministic assertions + normalized trace for libheif2shell.
# 24 invocations (gcc/clang x vuln/fixed x plain/asan x 3 scenarios).
# Normalized trace excludes PID, addresses, paths and build ids.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0
FAIL=0

expect() { # file expected-substring label
    if grep -qF -- "$2" "$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        printf 'FAIL %s: missing %s\n' "$3" "$2"
    fi
}
absent() { # file forbidden-substring label
    if grep -qF -- "$2" "$1"; then
        FAIL=$((FAIL+1))
        printf 'FAIL %s: unexpected %s\n' "$3" "$2"
    else
        PASS=$((PASS+1))
    fi
}
expect_line() { # file full-line label
    expect "$1" "$2" "$3"
}

run_all() {
    for cc in gcc clang; do
        for v in vuln fixed; do
            for mode in plain asan; do
                for sc in baseline oob-chosen grow-ok; do
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

for cc in gcc clang; do
    for v in vuln fixed; do
        for mode in plain asan; do
            for sc in baseline oob-chosen grow-ok; do
                f="$OUT/$mode-$cc-$v-$sc.out"
                tag="$mode-$cc-$v-$sc"
                if [ "$v" = vuln ] && [ "$mode" = asan ] && [ "$sc" = oob-chosen ]; then
                    # The vulnerable ASan build aborts inside the pinned memcpy.
                    expect "$f" 'ERROR: AddressSanitizer: heap-buffer-overflow' "$tag"
                    expect "$f" 'WRITE of size 64' "$tag"
                    expect "$f" 'pixelimage.cc.vuln:644' "$tag"
                    expect "$f" 'heif_image.cc.vuln:403' "$tag"
                    expect "$f" 'is located 0 bytes after 32768-byte region' "$tag"
                    expect "$f" 'EXIT=1' "$tag"
                else
                    # Every other run completes without sanitizer findings.
                    expect "$f" 'EXIT=0' "$tag"
                    absent "$f" 'ERROR: AddressSanitizer' "$tag"
                    if [ "$sc" = oob-chosen ] && [ "$v" = fixed ]; then
                        expect_line "$f" \
                          'GUARD scenario=oob-chosen req=512x64 plane=64x65 rc=2 msg=Cannot extend padding to a size smaller than the image.' "$tag"
                        expect_line "$f" \
                          'CASE scenario=oob-chosen guard=reject rc=2 copies=0' "$tag"
                    elif [ "$sc" = oob-chosen ]; then
                        expect_line "$f" \
                          'GUARD scenario=oob-chosen req=512x64 plane=64x65 rc=0 msg=-' "$tag"
                        expect_line "$f" \
                          'CASE scenario=oob-chosen guard=absent stride=512 b32768=5a b32769=5a b32770=5a b32771=5a' "$tag"
                    elif [ "$sc" = baseline ]; then
                        expect_line "$f" \
                          'GUARD scenario=baseline req=64x65 plane=64x65 rc=0 msg=-' "$tag"
                        expect_line "$f" \
                          'CASE scenario=baseline guard=absent copy=completed' "$tag"
                    else
                        expect_line "$f" \
                          'GUARD scenario=grow-ok req=512x128 plane=64x64 rc=0 msg=-' "$tag"
                        expect_line "$f" \
                          'CASE scenario=grow-ok guard=absent copy=completed' "$tag"
                    fi
                fi
            done
        done
    done
done

# Debugger observation of the chosen bytes beyond the declared plane.
if command -v gdb >/dev/null 2>&1; then
    gdb -q -batch \
        -ex 'break heif_dbg_mark' \
        -ex 'run oob-chosen' \
        -ex 'frame 1' \
        -ex 'printf "DBG rc=%d stride=%zu\n", e.code, img->m_storage[0].stride' \
        -ex 'x/4bx img->m_storage[0].mem + 32768' \
        "$HERE/bin-gcc-vuln-plain" > "$OUT/gdb-chosen.out" 2>&1 || true
    expect "$OUT/gdb-chosen.out" '0x5a' 'gdb-chosen'
fi

# Stable trace: normalize volatile fields before hashing.
: > "$OUT/trace.txt"
for cc in gcc clang; do
    for v in vuln fixed; do
        for mode in plain asan; do
            for sc in baseline oob-chosen grow-ok; do
                printf '=== %s-%s-%s-%s ===\n' "$mode" "$cc" "$v" "$sc" >> "$OUT/trace.txt"
                cat "$OUT/$mode-$cc-$v-$sc.out" >> "$OUT/trace.txt"
            done
        done
    done
done
if [ -f "$OUT/gdb-chosen.out" ]; then
    printf '=== gdb-chosen ===\n' >> "$OUT/trace.txt"
    cat "$OUT/gdb-chosen.out" >> "$OUT/trace.txt"
fi
sed -E \
    -e 's/==[0-9]+==/==PID==/g' \
    -e 's/0x[0-9a-f]{6,}/0xADDR/g' \
    -e 's/BuildId: [0-9a-f]+/BuildId: ID/g' \
    -e 's#/[^ ]*/lab/frontier/libheif2shell/#LAB/#g' \
    "$OUT/trace.txt" > "$OUT/trace.norm.txt"
mv "$OUT/trace.norm.txt" "$OUT/trace.txt"
TRACE=$(sha256sum "$OUT/trace.txt" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$TRACE" > "$OUT/summary.txt"
cat "$OUT/summary.txt"
rm -f "$OUT/.expected"
[ "$FAIL" -eq 0 ]
