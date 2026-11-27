#!/usr/bin/env python3
"""Re-check the 256 one-byte saved-RIP entries for an RBP-*write* gadget.

`gadget_sweep.py` treated every RBP reference as fatal, but a write such as
`mov rbp,rsp` / `lea rbp,[rsp+..]` / `pop rbp` would restore a canonical RBP
from the stack pointer after the ASCII overwrite, before the first control
transfer. This script decodes the pinned stock 4.0.1 no-canary module and
reports whether any of the 256 entry offsets contains such a write before
its first control transfer. Read-only: prints a table to stdout.

Requires ndisasm (nasm).
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
RBP = re.compile(r"\brbp\b|\(bp\)")
WRITE = re.compile(
    r"^(mov|lea|pop|xchg|add|sub|and|or|xor|inc|dec|neg|not|imul|shl|shr|"
    r"sar|rol|ror|adc|sbb)\s+(rbp|ebp|bp)\b")
CTRL = re.compile(r"^(ret|jmp|call|j[a-z]+|loop[a-z]*)\b")


def decode(data, origin, fd, path, n=20):
    with open(path, "wb") as fh:
        fh.write(data[:160])
    out = subprocess.run(
        ["ndisasm", "-b", "64", "-o", hex(origin), path],
        capture_output=True, check=True,
    ).stdout.decode(errors="replace")
    insns = []
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(3).strip()))
        if len(insns) == n:
            break
    return insns


def main():
    blob = open(MODULE, "rb").read()[START:END + 0x100]
    fd, path = tempfile.mkstemp()
    os.close(fd)
    writes = []
    mnemonics = collections.Counter()
    rets = []
    try:
        for off in range(END - START):
            first = None
            for addr, text in decode(blob[off:], START + off, fd, path):
                if WRITE.search(text):
                    writes.append((START + off, addr, text))
                if CTRL.match(text):
                    if text.startswith("ret"):
                        rets.append((START + off, addr, text))
                    mnemonics[text.split()[0]] += 1
                    first = (addr, text)
                    break
            if first is None:
                mnemonics["<none in 20>"] += 1
    finally:
        os.unlink(path)
    print("module:", MODULE)
    print("window: 0x%x-0x%x (%d entry offsets)" % (START, END, END - START))
    print("first control-transfer mnemonics:", dict(sorted(mnemonics.items())))
    print("RBP writes before first control transfer: %d" % len(writes))
    for off, addr, text in writes:
        print("  0x%04x: %04x %s" % (off, addr, text))
    print("bare ret (0xc3) entries:", sum(t == "ret" for _, _, t in rets))
    print("ret imm16 entries:", [(hex(o), hex(a), t) for o, a, t in rets if t != "ret"])
    return 0 if not writes else 1


if __name__ == "__main__":
    sys.exit(main())
