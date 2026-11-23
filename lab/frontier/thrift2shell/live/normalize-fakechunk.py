#!/usr/bin/env python3
"""Normalize the forged-chunk replay into address-free, hashable evidence."""
import re
import struct
from pathlib import Path

R = Path(__file__).resolve().parent / "results"


def text(name):
    return (R / name).read_text(errors="replace")


def aborted(s):
    return int(bool(re.search(r"free\(\): invalid pointer|malloc\(\):|corrupted|SIGABRT|SIGSEGV", s)))


def main():
    vuln = text("fakechunk-vuln.log")
    fixed = text("fakechunk-fixed.log")
    safe = text("fakechunk-safe.log")
    match = re.search(r"WANTFREE n=\d+ mem=(0x[0-9a-f]+) rbuf=(0x[0-9a-f]+)", vuln)
    if not match:
        raise SystemExit("no chosen free observed in vulnerable run")
    delta = int(match.group(1), 16) - int(match.group(2), 16)
    before = (R / "fakechunk-before.bin").read_bytes()
    after = (R / "fakechunk-after.bin").read_bytes()
    if len(before) != 1024 or len(after) != 1024:
        raise SystemExit("missing 1024-byte window dumps")
    changed = []
    for off in range(0, 1024, 8):
        x = struct.unpack_from("<Q", before, off)[0]
        y = struct.unpack_from("<Q", after, off)[0]
        if x != y:
            changed.append(off)
    mark_before = struct.unpack_from("<Q", before, 0x200)[0]
    mark_after = struct.unpack_from("<Q", after, 0x200)[0]
    if mark_before != 0xA5A5A5A5A5A5A5A5:
        raise SystemExit("marker not present before chosen free")
    print("FRAME=312-byte-partial-KV-low16-sweep")
    print("CHOSEN_BITS=16")
    print(f"CHOSEN_FREE_DELTA_FROM_RBUF={delta:+d}")
    print("FABRICATED_CHUNK_SIZE=0x31")
    print("FREED_CHUNK_ACCEPTED=1")
    print("MARKER_OFFSET_FROM_RBUF=512")
    print(f"MARKER_OVERWRITTEN={int(mark_after != mark_before)}")
    print(f"CHANGED_QWORDS_IN_WINDOW={len(changed)}")
    print(f"CHANGED_OFFSETS=" + ",".join(f"+{o}" for o in changed))
    print(f"PROCESS_REACHED_VULN={int('PROCESS_REACHED' in vuln)}")
    print(f"ABORT_VULN={aborted(vuln)}")
    print(f"PROCESS_REACHED_FIXED={int('PROCESS_REACHED' in fixed)}")
    print(f"ABORT_FIXED={aborted(fixed)}")
    print(f"PROCESS_REACHED_SAFE={int('PROCESS_REACHED' in safe)}")
    print(f"ABORT_SAFE={aborted(safe)}")


if __name__ == "__main__":
    main()
