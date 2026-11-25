#!/bin/sh
# W8 clean-groom replay: the pinned parent's own &buf[ih_hdr_size] write,
# with no harness OOB groom in the parent build. Wire bytes only; loopback.
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
sh serial-build.sh nogroom >/dev/null
sh serial-build.sh fixed >/dev/null

run_one()
{
    BIN=$1
    HDR=$2
    MODE=$3
    LOG="evidence/clean-$BIN-$HDR.log"
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
    if [ "$MODE" = clean ]; then
        CLIENT=$(python3 client.py "$PORT" "$HDR" fragmented clean)
    else
        CLIENT=$(python3 client.py "$PORT" "$HDR" fragmented)
    fi
    printf '%s\n' "$CLIENT" | tee -a "$LOG"
    wait "$SERVER" && RC=0 || RC=$?
    SERVER=
    echo "hdr_size=$HDR SERVER_RC=$RC" | tee -a "$LOG"
    grep -E 'REAL_DECRYPT|READBACK|SERIAL_DONE|SMP image|SMP_DONE' "$LOG" | tee -a "$LOG.clean-summary"
}

run_one smp-serial-nogroom 4104 clean
run_one smp-serial-fixed 4104 clean
run_one smp-serial-nogroom 2048 clean
for hdr in 5000 6000 7000; do
    run_one smp-serial-nogroom "$hdr" clean
done
echo "CLEAN_RUN_DONE"
