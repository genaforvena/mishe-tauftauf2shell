#!/usr/bin/env python3
"""Static sweep of the 256 one-byte saved-RIP target offsets.

The pinned stock 4.0.1 no-canary module has sha_hash at xmpp.so offset
0x5ea6; a 885-byte JID overwrites the low byte of the saved return address
and zeroes byte 1, so under the gdb-default base the target is one of
0x6000..0x60ff.  Any useful target must reach a control transfer before
touching the corrupted saved RBP (filled with ASCII by the same write).

Requires ndisasm (nasm).  Read-only: prints a table to stdout.
"""
import collections
import os
import re
import subprocess
import sys
import tempfile

MODULE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "401-plain", "modules", "xmpp", "xmpp.so")
START = 0x6000
END = 0x6100
LINE = re.compile(r"^\s*([0-9A-F]+)\s+([0-9A-F]+)\s+(.*)$")
CTRL = re.compile(r"\b(ret|jmp|call|j[a-z]+|loop[a-z]*)\b")
RBP = re.compile(r"\brbp\b|\(bp\)")


def decode(data, origin, n=12):
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        with open(path, "wb") as fh:
            fh.write(data)
        out = subprocess.run(
            ["ndisasm", "-b", "64", "-o", hex(origin), path],
            capture_output=True, check=True,
        ).stdout.decode(errors="replace")
    finally:
        os.unlink(path)
    insns = []
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(3).strip()))
        if len(insns) == n:
            break
    return insns


def main():
    blob = open(MODULE, "rb").read()[START:END]
    rows = []
    classes = collections.Counter()
    for off in range(END - START):
        insns = decode(blob[off:off + 96], START + off)
        used = False
        hit = None
        for addr, text in insns:
            if RBP.search(text):
                used = True
            if CTRL.search(text):
                hit = (addr, text, used)
                break
        if hit is None:
            cls = "no-control-transfer-in-12-insns"
        else:
            text = hit[1]
            if text.startswith("ret"):
                cls = "ret|rbp-before=%s" % hit[2]
            elif re.match(r"(jmp|call)\s+0x[0-9a-f]+$", text):
                cls = "relative-%s|rbp-before=%s" % (text.split()[0], hit[2])
            else:
                cls = "other|rbp-before=%s" % hit[2]
        classes[cls] += 1
        rows.append((START + off, cls, hit))
    print("module:", MODULE)
    print("window: 0x%x-0x%x (%d entry offsets)" % (START, END, END - START))
    print("classes:")
    for k, v in sorted(classes.items()):
        print("  %-42s %d" % (k, v))
    print("\nentries whose first control transfer has no prior rbp reference:")
    for addr, cls, hit in rows:
        if hit and not hit[2]:
            print("  0x%04x  %s  -> %s" % (addr, cls, hit[1]))
    print("\nNOTE: 'ret 0xNNNN' is ret imm16, not a bare ret; its target still")
    print("comes from [rsp] = saved-rbp+16, which the 885-byte write does not")
    print("set. Relative calls with 0xffffffff... targets are non-canonical.")


if __name__ == "__main__":
    sys.exit(main())
