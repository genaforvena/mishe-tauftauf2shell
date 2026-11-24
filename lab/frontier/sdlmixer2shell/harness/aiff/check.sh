#!/bin/sh
# Deterministic assertions + normalized trace for the AIFF sibling lane.
# 36 invocations (g++/clang++ x vuln/fixed x plain/asan/nossp x small/edge/attack)
# plus one gdb chosen-byte probe. Trace excludes PID, addresses and paths.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0
FAIL=0

expect() {
    if grep -qF "$2" "$1"; then PASS=$((PASS+1));
    else FAIL=$((FAIL+1)); printf 'FAIL %s: missing %s\n' "$3" "$2"; fi
}
absent() {
    if grep -qF "$2" "$1"; then FAIL=$((FAIL+1)); printf 'FAIL %s: found %s\n' "$3" "$2";
    else PASS=$((PASS+1)); fi
}
trace() { printf '%s\n' "$1" >> "$OUT/trace.txt"; }

: > "$OUT/trace.txt"
: > "$OUT/summary.txt"
for cxx in g++ clang++; do
  for v in vuln fixed; do
    for mode in plain asan nossp; do
      B="$cxx-$v-$mode"
      for sc in small edge attack; do
        F="$OUT/$B-$sc.out"
        set +e
        "$HERE/$B" "$sc" > "$F" 2>&1
        RC=$?
        set -e
        printf '%s %s rc=%d\n' "$B" "$sc" "$RC" >> "$OUT/summary.txt"

        if [ "$sc" = small ]; then
          expect "$F" 'rc=64 scenario=small' "$B-small"
          expect "$F" 'buffer[1023]=11' "$B-small-intact"
          absent "$F" 'AddressSanitizer' "$B-small-asan"
          trace "$B small clean rc=64"
        fi

        if [ "$v" = vuln ] && [ "$mode" = asan ] && [ "$sc" != small ]; then
          expect "$F" 'ERROR: AddressSanitizer: stack-buffer-overflow' "$B-$sc"
          expect "$F" 'WRITE of size 4' "$B-$sc"
          expect "$F" 'decoder_aiff.c.vuln:95' "$B-$sc"
          expect "$F" 'overflows this variable' "$B-$sc"
          if [ "$sc" = edge ]; then
            expect "$F" 'Memory access at offset 1056 overflows this variable' "$B-edge-offset"
          fi
          trace "$B $sc ASAN-STACK-WRITE4-95"
        fi

        if [ "$v" = vuln ] && [ "$mode" = plain ] && [ "$sc" = attack ]; then
          if [ "$RC" -eq 0 ]; then FAIL=$((FAIL+1)); printf 'FAIL %s-attack rc=0\n' "$B";
          else PASS=$((PASS+1)); fi
          if grep -qF 'stack smashing detected' "$F"; then
            expect "$F" 'stack smashing detected' "$B-attack"
            trace "$B attack glibc-canary-smash"
          else
            expect "$F" 'Segmentation fault' "$B-attack"
            trace "$B attack stack-fault-no-canary-message"
          fi
        fi
        if [ "$v" = vuln ] && [ "$mode" = plain ] && [ "$sc" = edge ]; then
          expect "$F" 'rc=516 scenario=edge buffer[0]=00 buffer[1023]=5a' "$B-edge"
          trace "$B edge 4-byte-past-canary-padding-survives"
        fi

        if [ "$v" = vuln ] && [ "$mode" = nossp ] && [ "$sc" != small ]; then
          if [ "$sc" = edge ]; then
            if [ "$RC" -eq 0 ]; then PASS=$((PASS+1));
            else FAIL=$((FAIL+1)); printf 'FAIL %s-edge rc=%d\n' "$B" "$RC"; fi
            expect "$F" 'rc=516 scenario=edge' "$B-edge"
            trace "$B edge no-canary-survives"
          else
            if [ "$RC" -ne 0 ]; then PASS=$((PASS+1));
            else FAIL=$((FAIL+1)); printf 'FAIL %s-attack rc=0\n' "$B"; fi
            trace "$B attack no-canary-segv"
          fi
        fi

        if [ "$v" = fixed ]; then
          absent "$F" 'AddressSanitizer' "$B-$sc-asan"
          absent "$F" 'stack smashing' "$B-$sc-canary"
          absent "$F" 'runtime error' "$B-$sc-ubsan"
          if [ "$sc" = edge ]; then
            expect "$F" 'rc=516 scenario=edge buffer[0]=5a buffer[1023]=11' "$B-edge"
          fi
          if [ "$sc" = attack ]; then
            expect "$F" 'rc=1024 scenario=attack buffer[0]=5a buffer[1023]=5a' "$B-attack"
          fi
          trace "$B $sc FIXED-clean"
        fi
      done
    done
  done
done

# Rung 4: chosen 0x5a5a5a5a at buffer+1024, observed in the live write.
G="$OUT/gdb-chosen.out"
gdb -q -batch \
  -ex 'break decoder_aiff.c.vuln:95' \
  -ex 'run edge' \
  -ex 'printf "I=%d LUT=%08x\n", i, *(unsigned int*)&lut[buffer[i]]' \
  -ex 'next' \
  -ex 'x/8xb buffer+1020' \
  "$HERE/g++-vuln-nossp" > "$G" 2>&1
expect "$G" 'I=128 LUT=5a5a5a5a' 'gdb-chosen-value'
bytes=$(grep -o '0x5a' "$G" | wc -l)
if [ "$bytes" -ge 4 ]; then PASS=$((PASS+1));
else FAIL=$((FAIL+1)); printf 'FAIL gdb-chosen-bytes: count=%s\n' "$bytes"; fi
trace 'gdb vuln edge I=128 LUT=5a5a5a5a chosen-bytes-at-buffer+1024'

HASH=$(sha256sum "$OUT/trace.txt" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d trace=%s\n' "$PASS" "$FAIL" "$HASH"
[ "$FAIL" -eq 0 ]
