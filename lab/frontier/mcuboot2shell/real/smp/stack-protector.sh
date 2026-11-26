#!/bin/sh
# W12: does the pinned OOB write survive a stack-protector-all build of the
# real loopback serial path? Wire bytes only; no harness groom.
set -eu
cd "$(dirname "$0")"
mkdir -p evidence
SERVER=
cleanup()
{
    if [ -n "$SERVER" ]; then
        kill "$SERVER" 2>/dev/null || :
        wait "$SERVER" 2>/dev/null || :
    fi
}
trap cleanup 0 1 2 15

OUT=smp-serial-sp ENC_INC=encryption-host.inc \
EXTRA_DEFS='-DM2S_SOCKET_UART -DMCUBOOT_SERIAL_WAIT_FOR_DFU -DMCUBOOT_SERIAL_INACTIVITY_TIMEOUT -DM2S_NO_GROOM' \
CFLAGS='-fstack-protector-all' sh build.sh >/dev/null

run_one()
{
    HDR=$1
    LOG="evidence/sp-$HDR.log"
    rm -f "$LOG"
    ./smp-serial-sp >"$LOG" 2>&1 &
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
    python3 client.py "$PORT" "$HDR" fragmented clean >>"$LOG" 2>&1
    wait "$SERVER" && RC=0 || RC=$?
    SERVER=
    printf 'hdr_size=%s SERVER_RC=%s ' "$HDR" "$RC" | tee -a evidence/stack-protector.txt
    if grep -qi 'stack smashing detected' "$LOG"; then
        echo 'CANARY=TRIPPED' | tee -a evidence/stack-protector.txt
    else
        echo 'CANARY=NOT_TRIPPED' | tee -a evidence/stack-protector.txt
    fi
    grep -E 'REAL_DECRYPT|READBACK|SERIAL_DONE|SMP image|SMP_DONE|stack smashing' "$LOG" || :
}

echo "STACK_PROTECTOR_START $(date -u +%FT%TZ)" >evidence/stack-protector.txt
run_one 4104
run_one 2048
# Restore the canonical nogroom binary after the variant build.
sh serial-build.sh nogroom >/dev/null
echo "STACK_PROTECTOR_DONE" | tee -a evidence/stack-protector.txt
