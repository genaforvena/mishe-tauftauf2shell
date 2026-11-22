#!/bin/bash
# W108 reach test: a *shipped* nanomsg process (nanocat from the pinned source
# trees) binds ws://127.0.0.1:28765 and reaches the same
# nn_ws_handshake_server_reply sink as harness/ws_server_dbg.
#
# Run from lab/frontier/nanomsg2shell: bash harness/nanocat_reach.sh
# Outputs land in harness/nanocat/ and contain ASLR addresses and PIDs, so
# they are deliberately NOT part of EVIDENCE_HASHES.txt.
set -u
cd "$(dirname "$0")/.." || exit 1
OUT=harness/nanocat
mkdir -p "$OUT"
PORT=28765

# Start one vuln or fixed nanocat listener; caller injects, then we stop it.
start_nanocat() { # $1 = build dir, $2 = case name
    LD_LIBRARY_PATH="src/$1" timeout 10s "src/$1/nanocat" \
        --rep --bind "ws://127.0.0.1:$PORT" \
        > "$OUT/server-$2.out" 2>&1 &
    SERVER_PID=$!
    sleep 1.5
}
stop_nanocat() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    sleep 0.3
}
inject() { # $1 = case name, $2 = n, $3 = mode
    python3 harness/wire_pattern.py "$2" "$3" 0 > "$OUT/client-$1.txt" 2>&1
    sleep 0.5
}
readback() { # $1 = case name, $2 = mode
    python3 harness/wire_pattern.py 489 "$2" 2 > "$OUT/client-gdb-$1.txt" 2>&1 &
    CLIENT_PID=$!
    LD_LIBRARY_PATH=src/build-dbg gdb -q -batch -x harness/gdb_dump.cmd \
        --args src/build-dbg/nanocat --rep --bind "ws://127.0.0.1:$PORT" \
        > "$OUT/gdb-$1.txt" 2>&1
    wait "$CLIENT_PID"
    sleep 0.3
}

echo "=== vuln 1.2.2 nanocat: short-header control ==="
start_nanocat build-dbg short
inject short 2 q
stop_nanocat
cat "$OUT/client-short.txt"
cat "$OUT/server-short.out"

for m in 41 ff; do
    echo "=== vuln 1.2.2 nanocat: marker:$m ==="
    start_nanocat build-dbg "vuln-marker-$m"
    inject "vuln-marker-$m" 489 "marker:$m"
    stop_nanocat
    cat "$OUT/client-vuln-marker-$m.txt"
    cat "$OUT/server-vuln-marker-$m.out"

    echo "=== fixed 1.2.3 nanocat: marker:$m ==="
    start_nanocat build-fixed-clang "fixed-marker-$m"
    inject "fixed-marker-$m" 489 "marker:$m"
    stop_nanocat
    cat "$OUT/client-fixed-marker-$m.txt"
    cat "$OUT/server-fixed-marker-$m.out"

    echo "=== vuln 1.2.2 nanocat: gdb readback marker:$m ==="
    readback "marker-$m" "marker:$m"
    grep -a -A1 -E 'VERSION_LEN|SELF=|item.next' "$OUT/gdb-marker-$m.txt" | tail -8
done

echo "=== done; raw evidence in $OUT/ ==="
