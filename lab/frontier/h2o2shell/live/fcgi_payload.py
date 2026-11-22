#!/usr/bin/env python3
"""Lab-only fake FastCGI upstream: emits one oversized FCGI_STDERR record.

Listens loopback-only. Records bytes received from h2o to a file, then sends a
FCGI_STDERR record whose content is either a fixed payload or a marker echoed
from the request headers (when --echo-header is given).
"""
import argparse
import socket
import struct
import time

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=17891)
ap.add_argument("--size", type=int, default=5000)
ap.add_argument("--byte", default="B")
ap.add_argument("--echo-header", default=None)
a = ap.parse_args()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", a.port))
srv.listen(1)
print("READY", flush=True)
conn, addr = srv.accept()
conn.settimeout(1.0)
data = b""
try:
    while len(data) < 65536:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
except socket.timeout:
    pass
open("/home/mesh-home/mishe-tauftauf2shell/lab/frontier/h2o2shell/live/fcgi-received.bin", "wb").write(data)
print("RECV", len(data), flush=True)

payload = (a.byte.encode() * a.size)[: a.size]
if a.echo_header:
    marker = a.echo_header.encode()
    idx = data.find(marker)
    if idx >= 0:
        end = data.find(b"\x00", idx)
        if end < 0:
            end = idx + a.size
            end = min(end, len(data))
        payload = data[idx + len(marker) : end][: a.size]
        print("ECHOED", len(payload), flush=True)
    else:
        print("MARKER-NOT-FOUND", flush=True)

rec = struct.pack("!BBHHBB", 1, 7, 1, len(payload), 0, 0) + payload
conn.sendall(rec)
print("SENT_STDERR", len(payload), flush=True)
time.sleep(0.3)
conn.close()
srv.close()
