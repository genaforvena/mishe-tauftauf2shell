#!/usr/bin/env python3
"""W178: assert the uncompressed-codec byte-exact OOB observation.

Usage: check_uncompressed.py EVIDENCE_DIR   (default: the committed evidence dir)
The inputs are the committed gdb log and plain run output; no rebuild or live
execution is needed. This checks author evidence, not an independent replay.
"""
import hashlib
import re
import sys
from pathlib import Path

EXPECTED_SHA = "b585565b5ca9af5860880c2102ae124749f298a5a3319e08a24e57cb8ca3a249"
ROW = bytes.fromhex("1122334455667788" * 8)


def main():
    here = Path(__file__).resolve().parent
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "evidence/uncompressed"
    check = []

    heif = d / "byte-exact.heif"
    digest = hashlib.sha256(heif.read_bytes()).hexdigest()
    check.append(("input sha256", digest == EXPECTED_SHA, digest))

    gdb = (d / "gdb-byte-exact.out").read_text(errors="replace")
    check.append(("OOB dest_off=32768", "OOB dest_off=32768" in gdb, ""))
    tail = gdb[gdb.find("OOB dest_off="):]
    lines = re.findall(r"^0x[0-9a-f]+:\s+((?:0x[0-9a-f]{2}\s+){7}0x[0-9a-f]{2})\s*$", tail, re.M)
    observed = bytes(int(b, 16) for line in lines[:8] for b in line.split()) if len(lines) >= 8 else b""
    check.append(("64-byte source row exact", observed == ROW, observed.hex()))

    after = gdb[gdb.find("--- offset 32768..32832 AFTER ---"):]
    after_lines = re.findall(r"^0x[0-9a-f]+:\s+(0x[0-9a-f]{16}(?:\s+0x[0-9a-f]{16})*)\s*$", after, re.M)
    landed = b"".join(int(w, 16).to_bytes(8, "little") for line in after_lines[:4] for w in line.split()) if len(after_lines) >= 4 else b""
    check.append(("64 bytes landed at plane+32768", landed == ROW, landed.hex()))

    plain = (d / "plain-byte-exact.out").read_text(errors="replace")
    check.append(("plain heap abort", "double free or corruption (out)" in plain, ""))

    for name, ok, detail in check:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" {detail}" if detail and not ok else ""))
    fails = sum(1 for _, ok, _ in check if not ok)
    print(f"PASS={len(check)-fails} FAIL={fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
