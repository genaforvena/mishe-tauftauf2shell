#!/usr/bin/env bash
# Full enforcer dp replay for CVE-2026-127182: build the pinned 5.5.x
# enforcer dataplane with ASan/-O2/no fortify/no stack protector, drive the
# REST-valid W274 message through the REAL AF_UNIX control socket, REAL
# jansson parser and REAL dp_ctrl_bld_dlp -> dpi_sig_bld call, and compare
# the fixed pinned commit. NOT rung 5: no chosen address, command or side
# effect. All fetching is provisioning under lab/; no external probe.
set -u
cd "$(dirname "$0")"
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

ROOT=$(readlink -f ../src/real/neuvector-48ae8b5cac5ec3a7e332e5272e9b3050f44396cb)
FIXED=$(readlink -f ../src/dpi_sig-fixed.c)
DEPS=$(readlink -f ../src/deps)
OUT=$(pwd)/out
SOCK=/tmp/dp_listen.sock
ATTACK=$(readlink -f ../wirepath/out/wire-attack.json)
SAFE=$(readlink -f ../wirepath/out/wire-safe.json)

echo "== provisioning pinned tree and build deps (lab-local only) =="
if [ ! -f "$ROOT/dp/dpi/sig/dpi_sig.c" ]; then
    mkdir -p ../src/real
    if [ ! -f ../src/real/neuvector-vuln.tar.gz ]; then
        curl -fsSL --max-time 180 \
          https://codeload.github.com/neuvector/neuvector/tar.gz/48ae8b5cac5ec3a7e332e5272e9b3050f44396cb \
          -o ../src/real/neuvector-vuln.tar.gz || {
            echo "FAIL pinned tree fetch"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
    fi
    tar xzf ../src/real/neuvector-vuln.tar.gz -C ../src/real || {
        echo "FAIL pinned tree extract"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
fi
RLIB=$DEPS/root/usr/lib/x86_64-linux-gnu
if [ ! -f "$RLIB/libhs.so" ]; then
    mkdir -p "$DEPS/debs" "$DEPS/root"
    (cd "$DEPS/debs" && apt-get download libjansson-dev liburcu-dev libpcap-dev \
        libpcre2-dev libjemalloc-dev libnetfilter-queue-dev libnfnetlink-dev \
        libhyperscan-dev libhyperscan5 >/dev/null 2>&1)
    for f in "$DEPS"/debs/*.deb; do dpkg-deb -x "$f" "$DEPS/root/"; done
    # dev symlinks point at runtime packages not extracted here; resolve them
    # from the host runtime libraries (lab-local symlink targets only).
    for s in $(find "$RLIB" -maxdepth 1 -xtype l -printf '%f\n'); do
        t=$(readlink "$RLIB/$s")
        for cand in /usr/lib/x86_64-linux-gnu/$t \
                    /usr/lib/x86_64-linux-gnu/${t%.so}.so.0 \
                    /usr/lib/x86_64-linux-gnu/${t%.so}.so.2 \
                    /usr/lib/x86_64-linux-gnu/${t%.so}.so.4 \
                    /usr/lib/x86_64-linux-gnu/${t%.so}.so.8 \
                    /usr/lib/x86_64-linux-gnu/${t%-8}.so.0 \
                    /usr/lib/x86_64-linux-gnu/${t%-posix}.so.3; do
            [ -e "$cand" ] && { ln -sfn "$cand" "$RLIB/$s"; break; }
        done
    done
    ln -sfn /usr/lib/x86_64-linux-gnu/libmnl.so.0 "$RLIB/libmnl.so"
fi
mkdir -p out "$DEPS/run"
[ -f "$RLIB/libhs.so" ] && ok "hyperscan dev provisioned under lab/" || bad "hyperscan dev provisioned under lab/"

echo "== source integrity =="
[ "$(sha256sum "$ROOT/dp/dpi/sig/dpi_sig.c" | cut -d' ' -f1)" = \
  1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b ] && \
    ok "pinned vulnerable enforcer source" || bad "pinned vulnerable enforcer source"
[ "$(sha256sum ../src/real/neuvector-vuln.tar.gz | cut -d' ' -f1)" = \
  8827c5f0de017392563119ac0f39429192c4233ccc150783e421f8c720148287 ] && \
    ok "pinned upstream tarball" || bad "pinned upstream tarball"
[ "$(sha256sum "$FIXED" | cut -d' ' -f1)" = \
  cc9d9c48ea07b015c7254946ab1c630f3aea2ce3a80d0042880b5cedaa284b08 ] && \
    ok "pinned fixed source" || bad "pinned fixed source"
[ "$(stat -c %s "$ATTACK")" = 2233 ] && ok "attack datagram is the REST-valid 2233-byte W274 message" || bad "attack datagram is the REST-valid 2233-byte W274 message"

echo "== build full dp, vulnerable and fixed =="
export PKG_CONFIG_PATH="$RLIB/pkgconfig"
CF="-Wall -Wno-unused-result -Wno-unused-function -fstrict-aliasing -g -O2 \
 -I$DEPS/root/usr/include -I$DEPS/root/usr/include/x86_64-linux-gnu \
 -I$DEPS/root/usr/include/hs -I$ROOT/dp -I$ROOT \
 $(pkg-config --cflags libnfnetlink libnetfilter_queue) \
 -fsanitize=address -fno-omit-frame-pointer -fno-stack-protector \
 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"
LF="-L$RLIB -Wl,-rpath,$RLIB -lpcap -lpcre2-8 -ljansson -ljemalloc -pthread \
 -lurcu -lurcu-cds -lrt -lstdc++ -lm -lnetfilter_queue -lnfnetlink -lmnl \
 -lhs -fsanitize=address"
build_dp() { (cd "$ROOT" && make -C dp/dpi/sig CFLAGS="$CF" >/dev/null 2>&1 && \
                    make -C dp CFLAGS="$CF" EXTRA_LDFLAGS="$LF" >/dev/null 2>&1); }
SAVE=$DEPS/dpi_sig-vulnerable-backup.c
cp "$ROOT/dp/dpi/sig/dpi_sig.c" "$SAVE"
restore() { cp "$SAVE" "$ROOT/dp/dpi/sig/dpi_sig.c"; build_dp; }
trap restore EXIT
build_dp && cp "$ROOT/dp/dp" "$OUT/dp-vuln" && \
    ok "full vulnerable enforcer dp builds with ASan" || bad "full vulnerable enforcer dp builds with ASan"
cp "$FIXED" "$ROOT/dp/dpi/sig/dpi_sig.c"
build_dp && cp "$ROOT/dp/dp" "$OUT/dp-fixed" && \
    ok "full fixed-commit enforcer dp builds with ASan" || bad "full fixed-commit enforcer dp builds with ASan"
restore; trap - EXIT
cmp -s "$SAVE" "$ROOT/dp/dpi/sig/dpi_sig.c" && ok "vulnerable pinned source restored" || bad "vulnerable pinned source restored"
nm "$OUT/dp-vuln" | grep -q ' T dpi_sig_bld' && ok "enforcer binary exports dpi_sig_bld" || bad "enforcer binary exports dpi_sig_bld"

echo "== live loopback datagram runs =="
run_case() {
    local bin="$1" msg="$2" log="$OUT/$3"
    rm -f "$SOCK"
    (cd "$DEPS/run" && ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
        timeout 12 "$bin" -s -n 1 > "$log" 2>&1) &
    local pid=$!
    for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
    if [ ! -S "$SOCK" ]; then echo "FAIL consumer did not bind $SOCK"; fail=$((fail+1)); wait "$pid" 2>/dev/null || true; return 1; fi
    python3 -c 'import socket,sys; d=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.sendto(d,sys.argv[2]); print("SENT bytes=%d"%len(d))' \
        "$msg" "$SOCK" >> "$OUT/$3.sent" 2>&1 || true
    sleep 2
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$SOCK"
}
run_case "$OUT/dp-vuln" "$ATTACK" dp-vuln-attack.log
run_case "$OUT/dp-vuln" "$SAFE"   dp-vuln-safe.log
run_case "$OUT/dp-fixed" "$ATTACK" dp-fixed-attack.log

echo "== vulnerable enforcer + attack datagram =="
has out/dp-vuln-attack.log.sent "SENT bytes=2233" && ok "real dp received the 2233-byte datagram" || bad "real dp received the 2233-byte datagram"
has out/dp-vuln-attack.log "AddressSanitizer: stack-buffer-overflow" && ok "full enforcer ASan stack overflow" || bad "full enforcer ASan stack overflow"
has out/dp-vuln-attack.log "WRITE of size 121" && ok "full enforcer ASan WRITE of size 121" || bad "full enforcer ASan WRITE of size 121"
has out/dp-vuln-attack.log "'dlpsig_buf' (line 621)" && ok "full enforcer write in real 2048-byte dlpsig_buf" || bad "full enforcer write in real 2048-byte dlpsig_buf"
has out/dp-vuln-attack.log "dpi_sig.c:658" && ok "full enforcer write frame is pinned sprintf" || bad "full enforcer write frame is pinned sprintf"
has out/dp-vuln-attack.log "dp_ctrl_bld_dlp" && ok "reach path is real dp_ctrl_bld_dlp" || bad "reach path is real dp_ctrl_bld_dlp"
has out/dp-vuln-attack.log "offset 2080 overflows this variable" && ok "write is 0 bytes past dlpsig_buf" || bad "write is 0 bytes past dlpsig_buf"

echo "== controls =="
hasnt out/dp-vuln-safe.log "AddressSanitizer" && ok "safe datagram: vulnerable enforcer ASan-clean" || bad "safe datagram: vulnerable enforcer ASan-clean"
hasnt out/dp-fixed-attack.log "AddressSanitizer" && ok "fixed enforcer: attack datagram ASan-clean" || bad "fixed enforcer: attack datagram ASan-clean"
has out/dp-fixed-attack.log "exceeds max sig len(2048)" && ok "fixed enforcer skips the oversized rule" || bad "fixed enforcer skips the oversized rule"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
