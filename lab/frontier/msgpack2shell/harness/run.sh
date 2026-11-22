#!/usr/bin/env bash
# Direct-call harness for CVE-2026-130065. Two rounds; gcc + clang; three pins.
set -u
export ASAN_OPTIONS=detect_leaks=0
cd "$(dirname "$0")" || exit 2

PINS="c-7.0.2 8a34070b 1c47ce0"
COMPILERS="gcc clang"
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -qF "$2" "$1"; then bad "$3"; else ok "$3"; fi; }
rc0() { if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }
rcnz() { if [ "$1" -ne 0 ]; then ok "$2"; else bad "$2"; fi; }

for f in raw-*.out raw-*.err raw-*.log evidence/*.log; do
    rm -f "$f"
done

# Regenerate the verbatim slices from the committed pins.
for pin in $PINS; do
    python3 gen_fn.py "../src/vrefbuffer-$pin.c" "fns-$pin.inc" || exit 2
    python3 verify_verbatim.py "fns-$pin.inc" "../src/vrefbuffer-$pin.c" || exit 2
done
sha256sum ../src/vrefbuffer-*.c ../src/fix-1c47ce0.patch > evidence/pin-hashes.txt

build() {
    local cc=$1 pin=$2 mode=$3 out=$4 extra=""
    case "$mode" in
        asan)  extra="-fsanitize=address" ;;
        plain) extra="-DPLAIN_MODE" ;;
        safe)  extra="-fsanitize=address -DSAFE_ONLY" ;;
    esac
    "$cc" -g -O0 -fno-omit-frame-pointer $extra \
        -DPIN="$pin" -DFNS="fns-$pin.inc" harness.c -o "$out"
}

for round in r1 r2; do
    for cc in $COMPILERS; do
        for pin in $PINS; do
            # --- ASan, overflow case ---
            b="$round-$cc-$pin-asan"
            build "$cc" "$pin" asan "$b" || { bad "build $b"; continue; }
            ./"$b" >"raw-$b.out" 2>"raw-$b.err"
            arcrc=$?
            cat "raw-$b.out" "raw-$b.err" >"raw-$b.log"
            python3 norm.py "raw-$b.log" "evidence/$b.log"
            case "$pin" in
                1c47ce0)
                    rc0 "$arcrc" "$b rc=0"
                    hasnt "raw-$b.log" "ERROR: AddressSanitizer" "$b no-asan"
                    has "raw-$b.log" "DST_CAP_AFTER=32" "$b grew-destination"
                    has "raw-$b.log" "DST_USED_AFTER=20" "$b used-20"
                    ;;
                *)
                    rcnz "$arcrc" "$b rc!=0"
                    has "raw-$b.log" "ERROR: AddressSanitizer: heap-buffer-overflow" "$b asan-oob"
                    has "raw-$b.log" "WRITE of size 320" "$b write-320"
                    has "raw-$b.log" "0 bytes after 128-byte region" "$b boundary"
                    has "raw-$b.log" "msgpack_vrefbuffer_migrate" "$b verbatim-frame"
                    ;;
            esac

            # --- Plain mode, chosen-byte readback ---
            b="$round-$cc-$pin-plain"
            build "$cc" "$pin" plain "$b" || { bad "build $b"; continue; }
            ./"$b" >"raw-$b.out" 2>"raw-$b.err"
            prcrc=$?
            cat "raw-$b.out" "raw-$b.err" >"raw-$b.log"
            python3 norm.py "raw-$b.log" "evidence/$b.log"
            rc0 "$prcrc" "$b rc=0"
            has "raw-$b.log" "OOB_FIRST_OFFSET=128" "$b offset-128"
            has "raw-$b.log" "OOB_CHOSEN_IOVECS=12" "$b twelve-chosen-iovecs"
            has "raw-$b.log" "OOB_FIRST_BASE=4141414141414141" "$b chosen-pointer"
            has "raw-$b.log" "OOB_FIRST_LEN=5a5a5a5a5a5a5a5a" "$b chosen-length"
            has "raw-$b.log" "OOB_TAIL_SENTINEL=INTACT" "$b tail-sentinel"
            if [ "$pin" = "1c47ce0" ]; then
                has "raw-$b.log" "OOB_PAST_CAP=-12" "$b fixed-in-bounds"
            else
                has "raw-$b.log" "OOB_PAST_CAP=12" "$b vuln-past-capacity"
            fi

            # --- Safe control under ASan, separate process ---
            b="$round-$cc-$pin-safe"
            build "$cc" "$pin" safe "$b" || { bad "build $b"; continue; }
            ./"$b" >"raw-$b.out" 2>"raw-$b.err"
            scrc=$?
            cat "raw-$b.out" "raw-$b.err" >"raw-$b.log"
            python3 norm.py "raw-$b.log" "evidence/$b.log"
            rc0 "$scrc" "$b rc=0"
            hasnt "raw-$b.log" "ERROR: AddressSanitizer" "$b no-asan"
            has "raw-$b.log" "INBOUND_CHOSEN=1" "$b inbound-chosen"
        done
    done
    cat evidence/"$round"-*.log > evidence/"$round"-normalized.txt
    sha256sum evidence/"$round"-normalized.txt > evidence/"$round"-normalized.sha
done

h1=$(awk '{print $1}' evidence/r1-normalized.sha)
h2=$(awk '{print $1}' evidence/r2-normalized.sha)
if [ "$h1" = "$h2" ]; then
    ok "two-round hash identical"
else
    bad "two-round hash differs ($h1 / $h2)"
fi
printf 'NORMALIZED_HASH=%s\n' "$h1"
printf 'TOTAL PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
