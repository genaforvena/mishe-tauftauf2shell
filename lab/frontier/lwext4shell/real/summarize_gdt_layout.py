#!/usr/bin/env python3
"""Summarize gdb readbacks of CVE-2025-71474 bit-set writes into the adjacent
live ext4_buf. Each section has two `x/18gx block_bitmap.buf` dumps (before and
after the loop at src/ext4_fs.c:333). The loop sets bits 0..bit_max-1 with
bit_max = 2 + s_reserved_gdt_blocks, so for a byte at absolute offset k from
block_bitmap.data the number of bits set is clamp(bit_max - 8*k, 0, 8):
covered bytes become 0xff, the boundary byte gets a low-bit prefix mask, and
bytes past the boundary are untouched. No byte can be set to an arbitrary
value, hence no chosen address or command pointer is reachable by this loop.
"""
import re
import sys

BUF_DELTA = 4112
FIELDS = [
    (0, 4, "flags"), (8, 8, "lba"), (16, 8, "data"),
    (24, 4, "lru_prio"), (28, 4, "lru_id"), (32, 4, "refctr"),
    (40, 8, "bc"), (48, 1, "on_dirty_list"),
    (56, 32, "lba_node"), (88, 32, "lru_node"), (120, 8, "dirty_node"),
    (128, 8, "end_write"), (136, 8, "end_write_arg"),
]
WORD_RE = re.compile(r"^0x[0-9a-f]+:\s+((?:0x[0-9a-f]{16}\s*)+)$", re.M)


def words_of(body):
    out = []
    for m in WORD_RE.finditer(body):
        for tok in m.group(1).split():
            out.append(int(tok, 16))
    if len(out) != 36:
        raise ValueError(f"expected 36 words, got {len(out)}")
    return out[:18], out[18:]


def as_bytes(words):
    return bytes(b for w in words for b in ((w >> (8 * j)) & 0xff for j in range(8)))


def field_value(data, off, size):
    return int.from_bytes(data[off:off + size], "little")


def expected_byte(before_byte, abs_off, bit_max):
    nset = max(0, min(8, bit_max - 8 * abs_off))
    return before_byte | ((1 << nset) - 1)


text = open(sys.argv[1], encoding="utf-8").read()
sections = re.split(r"^=== GDT=(\d+) ===$", text, flags=re.M)
layout_matched = 0
noptr_matched = 0
for i in range(1, len(sections) - 1, 2):
    gdt = int(sections[i])
    body = sections[i + 1]
    delta = re.search(r"^DELTA=(-?\d+) SIZEOF=(\d+)", body, re.M)
    if not delta or int(delta.group(1)) != BUF_DELTA or int(delta.group(2)) != 144:
        print(f"LAYOUT_BITS gdt={gdt} MATCH=0 reason=missing-or-wrong-delta")
        continue
    try:
        before_words, after_words = words_of(body)
    except ValueError as exc:
        print(f"LAYOUT_BITS gdt={gdt} MATCH=0 reason={exc}")
        continue
    before, after = as_bytes(before_words), as_bytes(after_words)
    bit_max = gdt + 2
    bad_bytes = 0
    for rel in range(144):
        if after[rel] != expected_byte(before[rel], BUF_DELTA + rel, bit_max):
            bad_bytes += 1
    touched = []
    for off, size, name in FIELDS:
        b, a = field_value(before, off, size), field_value(after, off, size)
        if b != a:
            touched.append(f"{name}:{b:#x}->{a:#x}")
    good = bad_bytes == 0
    layout_matched += int(good)
    print(f"LAYOUT_BITS gdt={gdt} delta={BUF_DELTA} words=18/18 "
          f"bad_bytes={bad_bytes} fields_touched={len(touched)} "
          f"fields={','.join(touched) if touched else '-'} MATCH={int(good)}")

    if gdt == 8:
        continue
    bw, aw = before_words, after_words
    end_write = aw[16]  # BUF+128
    bc_before, bc_after = bw[5], aw[5]  # BUF+40
    data_after = aw[2]  # BUF+16
    prefix_values = {(1 << k) - 1 for k in range(65)}
    no_ptr = (end_write in prefix_values
              and ((bc_after == 0xffffffffffffffff)
                   or ((bc_after & 0xffffffff00000000)
                       == (bc_before & 0xffffffff00000000)))
              and (data_after == 0 or data_after == 0xffffffffffffffff))
    noptr_matched += int(no_ptr)
    print(f"NO_CHOSEN_PTR gdt={gdt} end_write={end_write:#x} "
          f"bc={bc_after:#x} data={data_after:#x} MATCH={int(no_ptr)}")

print(f"LAYOUT_MATCHED={layout_matched}/9")
print(f"NO_CHOSEN_PTR_MATCHED={noptr_matched}/8")
sys.exit(0 if layout_matched == 9 and noptr_matched == 8 else 1)
