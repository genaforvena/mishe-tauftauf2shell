#!/usr/bin/env python3
"""Assert the saved gdb probe shows file-derived bytes past the plane.

Usage: check_neighbour.py evidence/gdb-neighbour.out
"""
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()


def section(start: str, end: str | None) -> str:
    i = text.index(start)
    j = text.index(end, i) if end else len(text)
    return text[i:j]


def bytes_of(block: str) -> bytes:
    vals = re.findall(r"0x([0-9a-f]{2})\b", block)
    return bytes(int(v, 16) for v in vals)


assert "PLANE=" in text, "no plane allocation captured"
assert "0x0000000000008021" in section("--- chunk header at plane-16", "Breakpoint 2"), \
    "unexpected malloc chunk header for the 32783-byte plane"

a = section("OOB_ROW_A", "A destination")
b = section("OOB_ROW_B", "STOP rip=")
a_pre = section("A destination", "Thread 1")
a_after = section("--- destination plane+32768 AFTER stores", "--- destination plane+33280")
b_after = section("--- destination plane+33280 AFTER stores", "#0 ")

assert "dest_off=32768" in a, "first OOB row not at plane+32768"
assert "dest_off=33280" in b, "second OOB row not at plane+33280"
assert "fault_dest_off=" in text, "no fault captured"

src_a, pre_a, after_a = bytes_of(a), bytes_of(a_pre), bytes_of(a_after)
src_b, after_b = bytes_of(b), bytes_of(b_after)
assert len(src_a) == len(pre_a) == len(after_a) == 64, "expected 64-byte rows"
assert len(src_b) == len(after_b) == 64, "expected 64-byte rows"
assert src_a == src_b, "two captured source rows differ"
assert src_a != pre_a, "source and pre-store destination are not distinguishable"
assert src_a == after_a, "file-derived bytes did not land at plane+32768"
assert src_b == after_b, "file-derived bytes did not land at plane+33280"
assert len(set(src_a)) > 1, "source row is uniform; pattern did not survive decoding"

# The next malloc chunk's size field sits at plane+32792 (row A offset 24).
old_size = int.from_bytes(pre_a[24:32], "little")
new_size = int.from_bytes(after_a[24:32], "little")
assert old_size not in (0, new_size), "next-chunk size field not observable before store"
assert new_size != old_size, "next-chunk size field was not overwritten"

print("PASS: patterned file bytes land byte-exact at plane+32768 and plane+33280")
print(f"      source row {src_a[:8].hex()}... ; next-chunk size 0x{old_size:x} -> 0x{new_size:x}")
