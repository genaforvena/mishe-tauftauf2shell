#!/usr/bin/env python3
"""Analyze YARV computed-goto handler pointers for the fixed-byte redirect lane.

The Ruby2Shell overflow writes a FIXED literal byte (0x53 upcase, 0x73 fold)
into the low byte of the adjacent chunk's first qword. When that qword is a
live iseq's iseq_encoded[0] handler pointer, the dispatched address becomes
    (handler & ~0xff) | byte
i.e. another offset in the same 256-byte page. This reaches a VALID handler
only if some dispatch-table entry lies at that exact offset on the SAME page.

This script dumps the table from a plain Ruby binary's `.data.rel.ro`, maps
each entry to an opcode via the tree's generated insns.inc, and reports
whether any reachable first-opcode handler has a 0x53/0x73 redirect target.

Usage:
  python3 lab/repro/ruby2shell-dispatch-table.py \
      <ruby-binary> <vm_exec_core-lo> <vm_exec_core-hi> <insns.inc>
"""
import re
import struct
import subprocess
import sys


def find_table(binary, lo, hi):
    """Longest run of 8-byte-aligned qwords in .data.rel.ro inside [lo, hi)."""
    out = subprocess.check_output(["readelf", "-S", "-W", binary], text=True)
    sections = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 7 and parts[0].startswith("[") and parts[1] == ".data.rel.ro":
            sections.append((int(parts[4], 16), int(parts[5], 16)))
    blob = open(binary, "rb").read()
    best = []
    for off, size in sections:
        n = size // 8
        for start in range(n):
            run = []
            cur = start
            while cur < n:
                value = struct.unpack_from("<Q", blob, off + cur * 8)[0]
                if lo <= value < hi:
                    run.append(value)
                    cur += 1
                else:
                    break
            if len(run) > len(best):
                best = run
    return best


def opcode_names(insns_inc):
    src = open(insns_inc).read()
    body = src.split("enum ruby_vminsn_type {", 1)[1].split("};", 1)[0]
    return re.findall(r"BIN\((\w+)\)", body)


# Opcodes that can actually appear as iseq_encoded[0] of a live iseq: every
# method body starts by loading self/args/locals or is a nop; comparison and
# trace opcodes require operands already on the stack and never lead a method.
FIRST_OPCODES = (
    "nop", "getlocal", "getlocal_WC_0", "getlocal_WC_1", "putnil", "putself",
    "putobject", "putspecialobject", "setlocal", "getinstancevariable",
    "definemethod", "defined",
)


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    binary, lo_s, hi_s, insns_inc = sys.argv[1:]
    lo, hi = int(lo_s, 0), int(hi_s, 0)
    table = find_table(binary, lo, hi)
    names = opcode_names(insns_inc)
    if len(table) != len(names):
        print(f"WARN table={len(table)} enum={len(names)} (index map may be off)")

    pages = {}
    for idx, value in enumerate(table):
        pages.setdefault(value >> 8, []).append((idx, value & 0xFF))
    target_pages = {
        page for page, entries in pages.items()
        if any(lb in (0x53, 0x73) for _, lb in entries)
    }

    print(f"binary={binary}")
    print(f"table entries={len(table)} pages={len(pages)}")
    print("valid-redirect pages (contain an entry at low byte 0x53 or 0x73):")
    for page in sorted(target_pages):
        entries = pages[page]
        print(f"  0x{page << 8:x}: " + ", ".join(
            f"{names[i] if i < len(names) else i}=0x{lb:02x}" for i, lb in entries
        ))

    reachable = []
    for name in FIRST_OPCODES:
        if name not in names:
            continue
        idx = names.index(name)
        if idx >= len(table):
            continue
        value = table[idx]
        page = value >> 8
        if page in target_pages:
            reachable.append((name, idx, value, page))
    if reachable:
        print("REACHABLE first-opcode redirects:")
        for name, idx, value, page in reachable:
            print(f"  {name} idx={idx} handler=0x{value:x} page=0x{page << 8:x}")
        print("verdict=REDIRECT_REACHABLE")
    else:
        print("no first-opcode handler shares a page with a 0x53/0x73 entry")
        print("verdict=NO_REACHABLE_REDIRECT")


if __name__ == "__main__":
    main()
