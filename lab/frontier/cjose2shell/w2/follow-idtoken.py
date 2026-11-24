#!/usr/bin/env python3
"""Follow-up GET /private that exposed the W186 heap corruption."""
import socket

HOST = "127.0.0.1"
PORT = 18443
REQ = (b"GET /private HTTP/1.1\r\n"
       b"Host: 127.0.0.1:18443\r\n"
       b"User-Agent: w2-idtoken-probe\r\n"
       b"Accept: text/html\r\n"
       b"Connection: close\r\n\r\n")

with socket.create_connection((HOST, PORT), timeout=10) as s:
    s.sendall(REQ)
    chunks = []
    while True:
        data = s.recv(4096)
        if not data:
            break
        chunks.append(data)
print(b"".join(chunks).split(b"\r\n", 1)[0].decode("ascii", "replace"))
