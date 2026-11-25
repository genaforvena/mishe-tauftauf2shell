#!/bin/sh
# W6: drive fragmented raw SMP bytes through MCUboot's real UART read loop.
# Each server binds only 127.0.0.1; no external traffic or physical serial.
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
sh serial-build.sh parent >/dev/null
sh serial-build.sh fixed >/dev/null

run_one()
{
    BIN=$1
    HDR=$2
    LOG="evidence/serial-$BIN-$HDR.log"
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
    CLIENT=$(python3 client.py "$PORT" "$HDR" fragmented)
    printf '%s\n' "$CLIENT" | tee -a "$LOG"
    wait "$SERVER" && RC=0 || RC=$?
    SERVER=
    echo "hdr_size=$HDR SERVER_RC=$RC" | tee -a "$LOG"
    cat "$LOG"
}

for hdr in 6144 7168 2048 4104; do
    run_one smp-serial "$hdr"
done
for hdr in 6144 7168 2048 4104; do
    run_one smp-serial-fixed "$hdr"
done
echo "SERIAL_RUN_DONE"
