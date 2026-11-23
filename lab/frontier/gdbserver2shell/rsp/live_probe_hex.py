#!/usr/bin/env python3
"""Loopback RSP client with an exact QTDPsrc payload, in hex.

Usage: live_probe_hex.py PORT HEXPAYLOAD [SLEN]
Sends QTDP, then one checksummed QTDPsrc frame whose decoded bytes are
exactly HEXPAYLOAD. The declared SLEN defaults to 1. Connects only to
127.0.0.1 on the port supplied by the caller.
"""
import socket
import sys


def frame(payload: bytes) -> bytes:
    return b"$" + payload + b"#" + ("%02x" % (sum(payload) & 0xFF)).encode()


def send(sock, payload: bytes):
    sock.sendall(frame(payload))
    while True:
        c = sock.recv(1)
        if not c:
            return "EOF"
        if c in (b"+", b"-"):
            return c.decode()


def recv(sock):
    data = bytearray()
    while True:
        c = sock.recv(1)
        if not c:
            return None
        if c == b"+":
            continue
        if c == b"$":
            data.clear()
            continue
        if c == b"#":
            sock.recv(2)
            sock.sendall(b"+")
            return bytes(data)
        data += c


def main():
    if len(sys.argv) < 3:
        print("usage: live_probe_hex.py PORT HEXPAYLOAD [SLEN]")
        return 2
    port = int(sys.argv[1])
    payload = bytes.fromhex(sys.argv[2])
    slen = int(sys.argv[3], 0) if len(sys.argv) > 3 else 1
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.settimeout(10)
        try:
            recv(s)
        except socket.timeout:
            pass
        send(s, b"QTDP:1:0:E:0:0")
        print("QTDP_REPLY=%s" % (recv(s) or b"").decode(errors="replace"))
        packet = b"QTDPsrc:1:0:cond:0:%x:%s" % (slen, payload.hex().encode())
        print("QTDPsrc_DECODED=%d DECLARED=%d" % (len(payload), slen),
              flush=True)
        send(s, packet)
        try:
            print("QTDPsrc_REPLY=%s" %
                  (recv(s) or b"").decode(errors="replace"))
        except (socket.timeout, ConnectionResetError) as e:
            print("QTDPsrc_REPLY_ERROR=%s" % type(e).__name__)
        try:
            send(s, b"qGetTLSAddr:1:0:0")
            print("GETTLS_REPLY=%s" %
                  (recv(s) or b"").decode(errors="replace"))
        except (socket.timeout, ConnectionResetError, OSError) as e:
            print("GETTLS_ERROR=%s" % type(e).__name__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
