#!/bin/bash
# W218 bounded identity probe: one crafted long bearer JWE through a fresh
# gdb-started Apache. Instruments malloc/free for the exact user pointer that
# W217's dump found 0x70 after the CEK. Loopback 127.0.0.1:18444 only.
set -eu
T=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
W2=$(CDPATH= cd -- "$T/.." && pwd)
GDBPIDS=""
cleanup() {
    if [ -f "$T/apache.pid" ]; then kill "$(cat "$T/apache.pid")" 2>/dev/null || true; rm -f "$T/apache.pid"; fi
    for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
    ss -ltn | grep -q ':18444 ' && { echo LISTENER_LEFT >&2; return 1; } || true
}
trap cleanup EXIT INT TERM
[ "$(ss -ltn | grep -cE ':18444 ' || true)" -eq 0 ] || { echo PORTS_BUSY >&2; exit 3; }
mkdir -p "$T/evidence" "$T/run" "$T/cache" "$T/html"
sed -e "s|@W2@|$W2|g" -e "s|@T@|$T|g" "$T/apache-w217.conf" > "$T/apache-vuln.run.conf"
sed "s|@LOG@|$T/evidence/gdb-w218-ident.log|" "$T/gdb-w218-ident.cmd" > "$T/gdb-w218-ident.run.cmd"
timeout 90 gdb -q -batch -x "$T/gdb-w218-ident.run.cmd" --args /usr/sbin/apache2 -f "$T/apache-vuln.run.conf" -X > "$T/evidence/stdout-w218-ident.log" 2>&1 &
GDBPIDS="$!"
for i in $(seq 1 150); do
    if ss -ltn | grep -q ':18444 '; then break; fi
    sleep 0.2
done
ss -ltn | grep -q ':18444 ' || { echo LISTENER_NOT_READY >&2; exit 2; }
W2_PORT=18444 W2_TAG=w218-ident python3 "$T/probe-w217.py" long > "$T/evidence/probe-w218-ident.log" 2>&1
sleep 3
for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
GDBPIDS=""
sleep 1
PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi; printf 'CHECK %-24s observed=%s expected=%s\n' "$1" "$2" "$3"; }
L="$T/evidence/gdb-w218-ident.log"
check KW_REACHED "$(grep -c 'W218_KW_DECRYPT raw_len=152' "$L" || true)" 1
check ALLOC_TARGET "$(grep -c 'W218_ALLOC_TARGET ptr=0x555555667350 size=56 caller=CRYPTO_zalloc' "$L" || true)" 1
check LOCK_STACK "$(grep -c 'CRYPTO_THREAD_lock_new' "$L" || true)" 1
check RAND_INIT "$(grep -c 'RAND_get_rand_method' "$L" || true)" 1
check JWE_ALLOC "$(grep -c '_cjose_jwe_malloc (bytes=32, random=true' "$L" || true)" 1
check CEK_TARGET "$(grep -c 'W218_CEK=0x5555556672e0 target_user=0x555555667350' "$L" || true)" 1
check FREE_TARGET "$(grep -c 'W218_FREE_TARGET' "$L" || true)" 0
check HTTP401 "$(grep -c '401 Unauthorized' "$T/evidence/probe-w218-ident.log" || true)" 1
ss -ltn | grep -E ':18444 ' || echo NO_LISTENER_LEFT
printf 'REPLAY_W218_IDENT: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
