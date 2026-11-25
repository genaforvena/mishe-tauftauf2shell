#!/bin/sh
# Bounded negative experiment: can the empty-boundary OOB sink write bytes
# chosen by the attacker? Compiles the pinned parser verbatim and feeds
# caller-chosen hex suffixes after the fixed CRLFCRLF framing.
set -u
cd "$(dirname "$0")/../.." || exit 1
mkdir -p harness/bytechoice/evidence
OUT=harness/bytechoice/evidence/bytechoice.txt
: >"$OUT"

cc -O0 -g -Iharness -Iprovision harness/bytechoice.c \
    provision/multipart_parser-v2.8.0.c -o harness/bytechoice-plain \
    >>"$OUT" 2>&1 || exit 1

# Twelve repetitions of the self-sustaining pattern (36 bytes).
CANON=
i=0
while [ "$i" -lt 12 ]; do CANON=${CANON}000d0a; i=$((i+1)); done
# Two arbitrary attacker suffixes of the same length.
ALL41=
ABC=
i=0
while [ "$i" -lt 36 ]; do ALL41=${ALL41}41; i=$((i+1)); done
i=0
while [ "$i" -lt 12 ]; do ABC=${ABC}414243; i=$((i+1)); done

case_run() {
    printf 'CASE=%s\n' "$1" >>"$OUT"
    harness/bytechoice-plain "$2" >>"$OUT" 2>&1 || return 1
}
case_run canonical "$CANON"
case_run all-0x41 "$ALL41"
case_run abc-repeat "$ABC"
j=0
while [ "$j" -lt 6 ]; do
    if [ "$j" -eq 0 ]; then PREFIXHEX=; else
        PREFIXHEX=$(printf '%s' "$CANON" | cut -c 1-$((j*2)))
    fi
    SUFFIXHEX=$(printf '%s' "$CANON" | cut -c $((j*2+3))-)
    case_run "mut-$j" "${PREFIXHEX}41${SUFFIXHEX}"
    j=$((j+1))
done
case_run crlf-restart "0d0a${CANON}0d0a${CANON}"

PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}
grep -q 'CASE=canonical' "$OUT" && grep -A2 'CASE=canonical' "$OUT" | grep -q 'CANARY=0a000d0a000d0a'
check 01-canonical-pattern-reaches-adjacent-heap "$?"
grep -A2 'CASE=all-0x41' "$OUT" | grep -q 'CANARY_CHANGED=0'
check 02-arbitrary-0x41-writes-nothing "$?"
grep -A2 'CASE=abc-repeat' "$OUT" | grep -q 'CANARY_CHANGED=0'
check 03-arbitrary-abc-writes-nothing "$?"
grep -A2 'CASE=crlf-restart' "$OUT" | grep -q 'CANARY=0a000d0a000d0a'
check 04-injected-crlf-only-restarts-forced-pattern "$?"
j=0
while [ "$j" -lt 6 ]; do
    grep -A2 "CASE=mut-$j" "$OUT" | grep 'CANARY=' | grep -qv '41'
    check "1$j-mut-$j-has-no-attacker-byte" "$?"
    j=$((j+1))
done
sha256sum -c pins.sha256 >>"$OUT" 2>&1
check 20-pins-exact "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
