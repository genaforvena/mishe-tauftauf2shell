#!/bin/sh
# Verify the real-caller harness: 12 binaries x 5 scenarios, with vulnerable,
# fixed and safe-input/parser-rejection controls. Evidence in evidence/.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence
PASS=0
FAIL=0
note() { printf '%s: %s\n' "$1" "$2"; }
check() { # label condition
    if [ "$2" = yes ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); note FAIL "$1"; fi
}
has() { grep -q -- "$2" "evidence/$1.out" 2>/dev/null && echo yes || echo no; }

for cxx in g++ clang++; do
    for v in vuln fixed; do
        for mode in plain asan nossp; do
            bin="$cxx-$v-$mode"
            for sc in safe edge ulaw badfmt pcm8; do
                tag="$bin-$sc"
                set +e
                ./"$bin" "$sc" >"evidence/$tag.out" 2>&1
                rc=$?
                set -e
                echo "$rc" >"evidence/$tag.rc"

                if [ "$sc" = badfmt ]; then
                    check "$tag parser rejection" "$(has "$tag" 'parse=REJECTED')"
                elif [ "$sc" = pcm8 ]; then
                    check "$tag PCM dispatch negative" "$(has "$tag" 'fetch=other')"
                    check "$tag PCM framesize" "$(has "$tag" 'decoded_framesize=1')"
                elif [ "$sc" = safe ]; then
                    check "$tag safe input runs" "$(has "$tag" 'parse=OK framesize=1 decoded_framesize=4 rc=1')"
                elif [ "$v" = fixed ]; then
                    check "$tag fixed fetch result" "$(has "$tag" 'parse=OK framesize=1 decoded_framesize=4 rc=1')"
                fi

                if [ "$sc" = ulaw ]; then fn=FetchULaw; else fn=FetchALaw; fi
                if [ "$mode" = asan ]; then
                    report=$(has "$tag" 'ERROR: AddressSanitizer: stack-buffer-overflow')
                    if [ "$v" = vuln ] && { [ "$sc" = edge ] || [ "$sc" = ulaw ]; }; then
                        check "$tag overflow report" "$report"
                        check "$tag pinned store line" "$(has "$tag" 'decoder_wav.c.vuln:759')"
                        check "$tag real dispatch frame" "$(has "$tag" "$fn")"
                        check "$tag real caller frame" "$(has "$tag" 'decoder_wav.c.vuln:1668')"
                        check "$tag WRITE of size 4" "$(has "$tag" 'WRITE of size 4')"
                    else
                        if [ "$report" = yes ]; then check "$tag no false positive" no
                        else check "$tag no false positive" yes; fi
                    fi
                fi
            done
        done
    done
done

# Normalized trace: one line per invocation (binary, scenario, exit code, first
# status line). Addresses, PIDs and timing are deliberately excluded.
: > evidence/trace.txt
for cxx in g++ clang++; do
    for v in vuln fixed; do
        for mode in plain asan nossp; do
            for sc in safe edge ulaw badfmt pcm8; do
                tag="$cxx-$v-$mode-$sc"
                first=$(grep -m1 -E 'scenario=|ERROR: AddressSanitizer' "evidence/$tag.out" 2>/dev/null || true)
                first=$(printf '%s' "$first" | sed -E 's/0x[0-9a-f]+/ADDR/g; s/[0-9]{4,}/NUM/g')
                printf '%s|%s|%s\n' "$tag" "$(cat "evidence/$tag.rc")" "$first" >> evidence/trace.txt
            done
        done
    done
done
hash=$(sha256sum evidence/trace.txt | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d trace=%s\n' "$PASS" "$FAIL" "$hash"
[ "$FAIL" -eq 0 ]
