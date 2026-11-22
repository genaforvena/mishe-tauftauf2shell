#!/usr/bin/env bash
# Direct-call harness for GHSA-jhg4-xcxm-cfg6 (ytnef DecompressRTF).
# Two rounds; gcc + clang; two pins; ASan and plain-arena cases.
set -u
export ASAN_OPTIONS=detect_leaks=0
cd "$(dirname "$0")" || exit 2

PINS="2.1.2 2.1.3"
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

# Regenerate and assert the verbatim slices from the committed pins.
for pin in $PINS; do
    python3 gen_fn.py "../src/ytnef-$pin.c" "fns-$pin.inc" >/dev/null || exit 2
    python3 verify_verbatim.py "fns-$pin.inc" "../src/ytnef-$pin.c" || exit 2
done
sha256sum ../src/ytnef-*.c ../src/fix-2.1.3.patch > evidence/pin-hashes.txt

build() {
    local cc=$1 pin=$2 mode=$3 out=$4 extra=""
    [ "$mode" = "asan" ] && extra="-fsanitize=address"
    [ "$mode" = "plain" ] && extra="-DPLAIN_MODE"
    "$cc" -g -O0 -fno-omit-frame-pointer $extra \
        -DPIN="\"$pin\"" -DFNS="\"fns-$pin.inc\"" harness.c -o "$out" || exit 2
}

run_case() {
    # $1 binary, $2 case, $3 tag; prints the process rc.
    ./"$1" "$2" >"raw-$3.out" 2>"raw-$3.err"
    local r=$?
    cat "raw-$3.out" "raw-$3.err" >"raw-$3.log"
    python3 norm.py "raw-$3.log" "evidence/$3.log"
    echo "$r"
}

for round in r1 r2; do
  for cc in $COMPILERS; do
    for pin in $PINS; do
      vuln=0
      [ "$pin" = "2.1.2" ] && vuln=1
      for mode in asan plain; do
        out="bin-$round-$cc-$pin-$mode"
        build "$cc" "$pin" "$mode" "$out"
        cases="write write0 write1 mela safe"
        [ "$mode" = "plain" ] && cases="write write0 write1 safe"
        for cas in $cases; do
          tag="$round-$cc-$pin-$mode-$cas"
          r=$(run_case "$out" "$cas" "$tag")
          log="evidence/$tag.log"
          if [ "$mode" = "asan" ]; then
            if [ "$vuln" -eq 1 ] && [ "$cas" != "safe" ]; then
              rcnz "$r" "$tag rc nonzero"
              has "$log" "ERROR: AddressSanitizer: heap-buffer-overflow" "$tag asan report"
              if [ "$cas" = "mela" ]; then
                has "$log" "READ of size 64" "$tag read 64"
                has "$log" "0 bytes after 20-byte region" "$tag 20-byte input"
              else
                has "$log" "WRITE of size 207" "$tag write 207"
                case "$cas" in
                  write) has "$log" "0 bytes after 16-byte region" "$tag 16-byte dst" ;;
                  write0) has "$log" "0 bytes after 1-byte region" "$tag zero-size dst" ;;
                  write1) has "$log" "0 bytes after 206-byte region" "$tag 206-byte dst" ;;
                esac
              fi
              has "$log" "in DecompressRTF" "$tag vulnerable frame"
            else
              rc0 "$r" "$tag rc zero"
              hasnt "$log" "ERROR: AddressSanitizer" "$tag no asan report"
              if [ "$vuln" -eq 1 ] || [ "$cas" = "safe" ]; then
                has "$log" "RESULT PIN=$pin CASE=safe OUT=nonnull OUTSIZE=8" "$tag safe output"
              else
                has "$log" "Corrupted file" "$tag fixed rejects"
              fi
            fi
          else
            rc0 "$r" "$tag rc zero"
            if [ "$cas" = "safe" ]; then
              has "$log" "SAFE_BAD=0" "$tag safe sentinel"
            elif [ "$vuln" -eq 1 ]; then
              has "$log" "CHOSEN_BAD=0" "$tag chosen bytes"
              case "$cas" in
                write) has "$log" "ALLOC=16 OVERRUN=191 B0=64 BMID=6f BEND=78 TAIL=ee" "$tag 191-byte extent" ;;
                write0) has "$log" "ALLOC=0 OVERRUN=207 B0=7b BMID=65 BEND=78 TAIL=ee" "$tag 207-byte extent" ;;
                write1) has "$log" "ALLOC=206 OVERRUN=1 B0=78 BMID=78 BEND=78 TAIL=ee" "$tag 1-byte extent" ;;
              esac
            else
              has "$log" "ALLOC=none OVERRUN=0 TAIL=ee" "$tag fixed no allocation"
              has "$log" "Corrupted file" "$tag fixed rejects"
            fi
          fi
        done
      done
    done
  done
done

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
