#!/usr/bin/env bash
# Loopback-only: run the pregrow server under gdb while a paced sender fills
# 4097 record numbers with a non-zero seq_base. No library source edits.
set -u
cd "$(dirname "$0")"
LOG=out/loopback/groom-abort3-gdb.log
gdb -q -batch -x groom_abort3.gdb ./out/loopback/server-groom > "$LOG" 2>&1 &
GP=$!
sleep 2
python3 loopback_frag_sender.py 18638 4097 0 1024 1200 legacy 1000 >> "$LOG" 2>&1
wait "$GP"
echo "gdb_rc=$?"
grep -E 'double free|_int_free_merge_chunk|__GI___libc_free|Dtls13RtxFlushAcks|ABORT_STOP3' "$LOG"
