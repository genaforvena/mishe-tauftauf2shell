#!/bin/sh
# W11 causal differential: with the harness OOB groom compiled in, the
# chosen bytes read back from the pinned &buf[ih_hdr_size] write follow the
# wire prefix; with M2S_NO_GROOM the 16-byte chosen pattern never appears and
# the observation changes in at most one byte when only the flash ciphertext
# changes. The pinned AES transform is in place (encrypted.c:722), so a clean
# bump's OOB source bytes are prior stack state, not the uploaded flash bytes.

set -eu
cd "$(dirname "$0")"
mkdir -p evidence
sh serial-build.sh parent >/dev/null
sh serial-build.sh nogroom >/dev/null

PT_A=WIRE-CHOICE-1234
PT_B=DIFF-WIRE-987654
CT_A=CTAAAAAAAAAAAAAA
CT_B=CTBBBBBBBBBBBBBB
HEX_A=574952452d43484f4943452d31323334
HEX_B=444946462d574952452d393837363534
OUT=evidence/wire-differential.txt
: >"$OUT"
SERVER=

cleanup()
{
    if [ -n "$SERVER" ]; then
        kill "$SERVER" 2>/dev/null || :
        wait "$SERVER" 2>/dev/null || :
    fi
}
trap cleanup 0 1 2 15

run_one()
{
    BIN=$1
    PT=$2
    CT=$3
    TAG=$4
    LOG="evidence/wire-diff-$TAG.log"
    rm -f "$LOG"
    "./$BIN" >"$LOG" 2>&1 &
    SERVER=$!
    READY=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if grep -q '^PORT=' "$LOG"; then READY=1; break; fi
        sleep 0.1
    done
    if [ "$READY" -ne 1 ]; then
        wait "$SERVER" || :
        cat "$LOG"
        exit 1
    fi
    PORT=$(awk -F= '/^PORT=/{print $2; exit}' "$LOG")
    M2S_WIRE_PT="$PT" M2S_CT_PT="$CT" python3 client.py "$PORT" 6144 fragmented clean | tee -a "$LOG"
    wait "$SERVER" && RC=0 || RC=$?
    SERVER=
    printf 'hdr_size=6144 SERVER_RC=%s\n' "$RC" | tee -a "$LOG"
    printf '%s server_rc=%s\n' "$TAG" "$RC" >>"$OUT"
}

check_common()
{
    TAG=$1
    LOG="evidence/wire-diff-$TAG.log"
    grep -q 'dst_delta=6144' "$LOG" || { echo "FAIL $TAG: no src_delta=6144" >>"$OUT"; exit 1; }
    grep -q '^hdr_size=6144 SERVER_RC=0$' "$LOG" || { echo "FAIL $TAG: server rc" >>"$OUT"; exit 1; }
    grep -q "SMP wire_plaintext=" "$LOG" || { echo "FAIL $TAG: missing wire plaintext marker" >>"$OUT"; exit 1; }
}

get_readback()
{
    awk -F'first16=' '/^READBACK delta=6144 / && $2 != "" {v=$2} END {print v}' "evidence/wire-diff-$1.log"
}

run_one smp-serial "$PT_A" "$CT_A" groom-a
run_one smp-serial "$PT_B" "$CT_A" groom-b
run_one smp-serial-nogroom "$PT_A" "$CT_A" clean-a
run_one smp-serial-nogroom "$PT_A" "$CT_B" clean-b

for tag in groom-a groom-b clean-a clean-b; do check_common "$tag"; done

GA=$(get_readback groom-a)
GB=$(get_readback groom-b)
CA=$(get_readback clean-a)
CB=$(get_readback clean-b)

printf 'groom-a readback=%s\n' "$GA" >>"$OUT"
printf 'groom-b readback=%s\n' "$GB" >>"$OUT"
printf 'clean-a readback=%s\n' "$CA" >>"$OUT"
printf 'clean-b readback=%s\n' "$CB" >>"$OUT"

[ "$GA" = "$HEX_A" ] || { echo "FAIL groom-a readback" >>"$OUT"; exit 1; }
[ "$GB" = "$HEX_B" ] || { echo "FAIL groom-b readback" >>"$OUT"; exit 1; }
DIFF_BYTES=$(python3 -c 'import sys; a,b=sys.argv[1:3]; print(sum(x!=y for x,y in zip(bytes.fromhex(a),bytes.fromhex(b))))' "$CA" "$CB")
printf 'clean readback byte_diff=%s (of 16)\n' "$DIFF_BYTES" >>"$OUT"
[ -n "$CA" ] && [ -n "$CB" ] || { echo "FAIL clean readback empty" >>"$OUT"; exit 1; }
[ "$DIFF_BYTES" -le 1 ] || { echo "FAIL clean readback differs in $DIFF_BYTES bytes" >>"$OUT"; exit 1; }
[ "$CA" != "$HEX_A" ] && [ "$CA" != "$HEX_B" ] && [ "$CB" != "$HEX_A" ] && [ "$CB" != "$HEX_B" ] || { echo "FAIL clean readback tracked chosen pattern" >>"$OUT"; exit 1; }
echo "WIRE_DIFFERENTIAL_OK" | tee -a "$OUT"
