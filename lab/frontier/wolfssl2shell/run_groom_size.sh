#!/usr/bin/env bash
# Loopback-only size-field control probe. Usage: run_groom_size.sh PORT SEQ_BASE_HEX LOG
# Runs the verbatim-pinned plain build; only the wrapper's pregrow precondition
# and the sender's 48-bit seq base vary. No library source edits.
set -u
cd "$(dirname "$0")"
PORT=${1:-18640}
SEQ=${2:-0}
LOG=${3:-out/loopback/groom-size-control.log}
mkdir -p "$(dirname "$LOG")"
gdb -q -batch -ex 'break dtls13.c:780' -ex "run $PORT 60 1 1 64" \
    -x groom_size.gdb ./out/loopback/server-groom > "$LOG" 2>&1 &
GP=$!
sleep 2
python3 loopback_frag_sender.py "$PORT" 4097 0 1024 1200 legacy "$SEQ" >> "$LOG" 2>&1
wait "$GP"
RC=$?
echo "gdb_rc=$RC log=$LOG seq_base=0x$SEQ"
grep -E 'FACT (FLUSH|SIZEFIELD|CHUNKQWORDS|POST_INFERIOR|final_ack_count|got_timeout_ret)|double free|_int_free_merge_chunk|exited normally|signal|SIGABRT' "$LOG"
