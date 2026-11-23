#!/usr/bin/env python3
"""Loopback RSP client for a plant-started pinned gdbserver.

Sends a QTDP packet to create a tracepoint, then one QTDPsrc packet with
a deliberately short declared SLEN. Never contacts anything but the
127.0.0.1 port passed on the command line.
"""
import socket
import sys

USAGE = "live_probe.py PORT MODE [N]"


def frame(payload: bytes) -> bytes:
    return b"$" + payload + b"#" + ("%02x" % (sum(payload) & 0xFF)).encode()


def send(sock, payload: bytes):
    """Send one frame and consume the server's '+' / '-' acknowledgement."""
    sock.sendall(frame(payload))
    while True:
        c = sock.recv(1)
        if not c:
            return "EOF"
        if c in (b"+", b"-"):
            return c.decode()


def recv(sock):
    """Receive one framed packet and acknowledge it, as a real GDB client."""
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
        print(USAGE)
        return 2
    port = int(sys.argv[1])
    mode = sys.argv[2]
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 64
    pattern = bytes((0x41 + (i & 0x1F)) for i in range(n))
    hexbytes = pattern.hex().encode()
    slen = n if mode == "safe" else 1
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.settimeout(10)
        try:
            initial = recv(s)
        except socket.timeout:
            initial = None
        print("INITIAL=%s" % (initial.decode(errors="replace") if initial else ""))
        ack = send(s, b"QTDP:1:0:E:0:0")
        reply = recv(s)
        print("QTDP_ACK=%s QTDP_REPLY=%s" %
              (ack, reply.decode(errors="replace") if reply else ""))
        packet = b"QTDPsrc:1:0:cond:0:%x:%s" % (slen, hexbytes)
        print("QTDPsrc_LEN=%d DECLARED=%d USEDLEN=%d" %
              (len(packet), slen, n), flush=True)
        ack = send(s, packet)
        print("QTDPsrc_ACK=%s" % ack, flush=True)
        try:
            reply = recv(s)
        except (socket.timeout, ConnectionResetError) as e:
            print("QTDPsrc_REPLY_ERROR=%s" % type(e).__name__)
            return 0
        print("QTDPsrc_REPLY=%s" %
              (reply.decode(errors="replace") if reply else ""))
        try:
            ack = send(s, b"qGetTLSAddr:1:0:0")
            reply = recv(s)
            print("GETTLS_ACK=%s GETTLS_REPLY=%s" %
                  (ack, reply.decode(errors="replace") if reply else ""))
        except (socket.timeout, ConnectionResetError, OSError) as e:
            print("GETTLS_ERROR=%s" % type(e).__name__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
