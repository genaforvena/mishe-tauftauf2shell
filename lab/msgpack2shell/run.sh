#!/usr/bin/env bash
# Real public-API differential for GHSA-8pq6-mw7r-9f5g / CVE-2026-130065.
# Two compilers x two pins x two modes; 2 vrefbuffer API sequences + canary PoC.
set -u
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
cd "$(dirname "$0")" || exit 2
mkdir -p evidence

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -qF "$2" "$1"; then bad "$3"; else ok "$3"; fi; }
rcnz() { if [ "$1" -ne 0 ]; then ok "$2"; else bad "$2"; fi; }
rc0() { if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }

rm -f evidence/raw-* evidence/api-* evidence/canary-* evidence/summary.txt

sha256sum src/vrefbuffer-*.c include/msgpack/vrefbuffer.h include/msgpack/zone.h > evidence/pin-hashes.txt || exit 2

: > evidence/summary.txt
for cc in gcc clang; do
    for pin in c-7.0.2 1c47ce0; do
        src="src/vrefbuffer-$pin.c"
        for mode in asan plain; do
            san=""; [ "$mode" = asan ] && san="-fsanitize=address -fno-omit-frame-pointer"
            out="evidence/api-$cc-$pin-$mode"
            $cc -g -O0 $san -I include api_repro.c "$src" -o "$out.bin" 2>"$out.build.err" || {
                bad "build $cc $pin $mode"; continue;
            }
            ok "build $cc $pin $mode"

            # Upstream two-migrate variant: 4 refs into A between the two migrates.
            ./"$out.bin" 4 >"$out-n4.out" 2>"$out-n4.err"; rc=$?
            if [ "$pin" = 1c47ce0 ]; then
                rc0 "$rc" "$cc $pin $mode n4 rc=0"
                has "$out-n4.out" 'B after migrate2: cap=16 used=9' "$cc $pin $mode n4 grew-to-16"
                hasnt "$out-n4.err" 'ERROR: AddressSanitizer' "$cc $pin $mode n4 no-asan"
                printf '%s %s %s n4 rc=%s grew=16 asan=no\n' "$cc" "$pin" "$mode" "$rc" >> evidence/summary.txt
            else
                rcnz "$rc" "$cc $pin $mode n4 rc!=0"
                if [ "$mode" = asan ]; then
                    has "$out-n4.err" 'ERROR: AddressSanitizer: heap-buffer-overflow' "$cc $pin $mode n4 asan-oob"
                    has "$out-n4.err" 'WRITE of size 64' "$cc $pin $mode n4 write-64"
                    has "$out-n4.err" 'in msgpack_vrefbuffer_migrate' "$cc $pin $mode n4 frame-migrate"
                    has "$out-n4.err" '0 bytes after 128-byte region' "$cc $pin $mode n4 zero-after-128"
                    printf '%s %s %s n4 rc=%s asan=WRITE64:0after128:migrate\n' "$cc" "$pin" "$mode" "$rc" >> evidence/summary.txt
                else
                    has "$out-n4.err" 'free(): invalid size' "$cc $pin $mode n4 glibc-canary"
                    printf '%s %s %s n4 rc=%s glibc=invalid-size\n' "$cc" "$pin" "$mode" "$rc" >> evidence/summary.txt
                fi
            fi

            # Equal-capacity safe control: 2 refs into A, B stays within 8 slots.
            ./"$out.bin" 2 >"$out-n2.out" 2>"$out-n2.err"; rc=$?
            rc0 "$rc" "$cc $pin $mode n2 rc=0"
            has "$out-n2.out" 'B after migrate2: cap=8 used=7' "$cc $pin $mode n2 in-bounds"
            hasnt "$out-n2.err" 'ERROR: AddressSanitizer' "$cc $pin $mode n2 no-asan"

            # The buggy comparison really does read false with natural pointers.
            has "$out-n4.out" 'cmp=0' "$cc $pin $mode n4 cross-object-cmp-false"
        done

        # Upstream single-migrate plain-glibc canary PoC.
        out="evidence/canary-$cc-$pin"
        $cc -g -O1 -I include canary_poc.c "$src" -o "$out.bin" 2>"$out.build.err" || {
            bad "build canary $cc $pin"; continue;
        }
        ./"$out.bin" >"$out.out" 2>"$out.err"; rc=$?
        if [ "$pin" = 1c47ce0 ]; then
            rc0 "$rc" "canary $cc $pin rc=0"
            has "$out.out" 'canary sentinel: intact' "canary $cc $pin intact"
            printf 'canary %s %s rc=%s intact=yes\n' "$cc" "$pin" "$rc" >> evidence/summary.txt
        else
            rcnz "$rc" "canary $cc $pin rc!=0"
            has "$out.out" 'canary sentinel: CORRUPTED' "canary $cc $pin corrupted"
            printf 'canary %s %s rc=%s corrupted=yes\n' "$cc" "$pin" "$rc" >> evidence/summary.txt
        fi
    done
done

sha256sum evidence/summary.txt > evidence/summary.sha
printf 'SUMMARY_HASH=%s\n' "$(awk '{print $1}' evidence/summary.sha)"
printf 'TOTAL PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
