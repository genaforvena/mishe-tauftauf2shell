#!/usr/bin/env bash
# Direct-call harness for CVE-2026-116791. Two rounds; gcc + clang; two pins.
set -u
export ASAN_OPTIONS=detect_leaks=0
cd "$(dirname "$0")" || exit 2

PINS="1.13.17 1.13.18"
COMPILERS="gcc clang"
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -qF "$2" "$1"; then bad "$3"; else ok "$3"; fi; }
rc0() { if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }
rcnz() { if [ "$1" -ne 0 ]; then ok "$2"; else bad "$2"; fi; }

rm -f raw-*.out raw-*.err raw-*.log evidence/*.log evidence/pin-hashes.txt

# Regenerate the verbatim slices from the committed pins.
for pin in $PINS; do
    python3 gen_fn.py "../src/ws-$pin.c" "fns-$pin.inc" >/dev/null || exit 2
    python3 verify_verbatim.py "fns-$pin.inc" "../src/ws-$pin.c" || exit 2
done
sha256sum ../src/ws-*.c ../src/ws-*.h ../src/fix-1.13.18.patch > evidence/pin-hashes.txt

build() {
    local cc=$1 pin=$2 mode=$3 out=$4 extra=""
    case "$mode" in
        asan)    extra="-fsanitize=address" ;;
        plain)   extra="-DPLAIN_MODE" ;;
    esac
    local fixed=""
    [ "$pin" = "1.13.18" ] && fixed="-DPIN_FIXED"
    "$cc" -g -O0 -fno-omit-frame-pointer $extra \
        -DPIN="\"$pin\"" -DFNS="\"fns-$pin.inc\"" $fixed \
        harness.c -o "$out"
}

run_case() {
    # $1 binary, $2 case (vuln|safe), $3 tag; prints "RC TAG"
    ./"$1" "$2" >"raw-$3.out" 2>"raw-$3.err"
    local r=$?
    cat "raw-$3.out" "raw-$3.err" >"raw-$3.log"
    python3 norm.py "raw-$3.log" "evidence/$3.log"
    echo "$r"
}

for round in r1 r2; do
    for cc in $COMPILERS; do
        for pin in $PINS; do
            # --- ASan, overflow case ---
            b="$round-$cc-$pin-asan-vuln"
            build "$cc" "$pin" asan "$b" || { bad "build $b"; continue; }
            rc=$(run_case "$b" vuln "$b")
            if [ "$pin" = "1.13.17" ]; then
                rcnz "$rc" "$b rc!=0"
                has "raw-$b.log" "ERROR: AddressSanitizer: heap-buffer-overflow" "$b asan-oob"
                has "raw-$b.log" "READ of size 1" "$b read-1"
                has "raw-$b.log" "0 bytes after 64-byte region" "$b boundary"
                has "raw-$b.log" "in ws_read_frame" "$b verbatim-frame"
                has "raw-$b.log" "PRECALL PAYLOAD=64 BBUFLEN=64" "$b setup-state"
            else
                rc0 "$rc" "$b rc=0"
                hasnt "raw-$b.log" "ERROR: AddressSanitizer" "$b no-asan"
                has "raw-$b.log" "ASAN_CASE_DONE vuln" "$b fixed-clean"
                has "raw-$b.log" "DATALEN=78 RPLEN=64" "$b state"
            fi

            # --- ASan, safe case (-16 payload) ---
            b="$round-$cc-$pin-asan-safe"
            build "$cc" "$pin" asan "$b" || { bad "build $b"; continue; }
            rc=$(run_case "$b" safe "$b")
            rc0 "$rc" "$b rc=0"
            hasnt "raw-$b.log" "ERROR: AddressSanitizer" "$b no-asan"
            has "raw-$b.log" "ASAN_CASE_DONE safe" "$b safe-clean"

            # --- Plain, chosen-byte readback ---
            b="$round-$cc-$pin-plain-vuln"
            build "$cc" "$pin" plain "$b" || { bad "build $b"; continue; }
            rc=$(run_case "$b" vuln "$b")
            if [ "$pin" = "1.13.17" ]; then
                rc0 "$rc" "$b rc=0"
                has "raw-$b.log" "CHOSEN_BAD=0" "$b chosen-ok"
                has "raw-$b.log" "NUL=00" "$b nul"
                has "raw-$b.log" "B1=b4" "$b chosen-b1"
                has "raw-$b.log" "B2=ac" "$b chosen-b2"
                has "raw-$b.log" "B3=ad" "$b chosen-b3"
                has "raw-$b.log" "B13=b4" "$b chosen-b13"
                has "raw-$b.log" "TAIL=ee" "$b extent"
            else
                rcnz "$rc" "$b rc!=0"
                has "raw-$b.log" "CHOSEN_BAD=1" "$b fixed-no-write"
                has "raw-$b.log" "B1=ee" "$b fixed-b1"
                has "raw-$b.log" "TAIL=ee" "$b fixed-tail"
            fi

            # --- Plain, safe case ---
            b="$round-$cc-$pin-plain-safe"
            build "$cc" "$pin" plain "$b" || { bad "build $b"; continue; }
            rc=$(run_case "$b" safe "$b")
            rc0 "$rc" "$b rc=0"
            has "raw-$b.log" "SAFE_BAD=0" "$b safe-sentinel"
        done
    done
done

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
