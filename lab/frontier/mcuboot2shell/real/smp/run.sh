#!/bin/sh
# Native SMP upload lane: real boot_serial.c + zcbor + pinned decrypt.
# Each run starts a fresh 127.0.0.1 listener and sends one mcumgr upload
# request whose CBOR "data" field is a 32-byte MCUboot image header with the
# tested ih_hdr_size. No off-loopback traffic.
set -eu
cd "$(dirname "$0")"
mkdir -p evidence
sh build.sh >/dev/null

for hdr in 6144 7168 2048 4104; do
    LOG="evidence/smp-$hdr.log"
    rm -f "$LOG"
    ./smp-host >"$LOG" 2>&1 &
    SERVER=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if grep -q '^PORT=' "$LOG"; then break; fi
        sleep 0.1
    done
    PORT=$(awk -F= '/^PORT=/{print $2; exit}' "$LOG")
    python3 client.py "$PORT" "$hdr"
    wait "$SERVER" && RC=0 || RC=$?
    echo "hdr_size=$hdr SERVER_RC=$RC" | tee -a "$LOG"
    cat "$LOG"
done
echo "SMP_RUN_DONE"
