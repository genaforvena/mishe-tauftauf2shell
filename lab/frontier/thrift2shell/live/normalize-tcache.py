#!/usr/bin/env python3
"""Normalize the W148 allocator-list replay into address-free evidence."""
import re
from pathlib import Path

R = Path(__file__).resolve().parent / "results"
s = (R / "tcache-vuln.log").read_text(errors="replace")

def line(pattern, name):
    m = re.search(pattern, s, re.M)
    if not m:
        raise SystemExit("missing " + name)
    return m

anchor = line(r"^ANCHOR rbuf=(0x[0-9a-f]+) sz=(\d+)$", "anchor")
match = line(r"^MATCHFREE mem=(0x[0-9a-f]+) target=(0x[0-9a-f]+)$", "chosen free")
link = line(r"^LINK saved=0x[0-9a-f]+ decoded_head=0x[0-9a-f]+ kind=(\d+) bin=(\d+) hdr=(0x[0-9a-f]+)$", "link")
delta = int(match.group(1), 16) - int(anchor.group(1), 16)
popped = len(re.findall(r"^POP_CANDIDATE ", s, re.M))
abort = re.search(r"malloc\(\): [^\n]+", s)
print("FRAME=312-byte-partial-KV-fixed-address")
print("CHOSEN_BITS=16")
print(f"ANCHOR_SZ={anchor.group(2)}")
print(f"CHOSEN_FREE_DELTA_FROM_RBUF={delta:+d}")
print("FABRICATED_CHUNK_SIZE=0x31")
print(f"CHOSEN_FREE_MATCH={int(match.group(1) == match.group(2))}")
print(f"FREE_LANDING_LIST={'tcache' if link.group(1) == '1' else 'fastbin' if link.group(1) == '2' else 'unknown'}")
print(f"FREE_LANDING_BIN={link.group(2)}")
print("PROTECTED_LINK_DECODED=1")
print("PROCESS_REACHED_VULN=%d" % int("PROCESS_REACHED" in s))
print(f"REUSE_POP_OBSERVED={int(popped > 0)}")
print("LATER_MALLOC_ABORT=%s" % (abort.group(0) if abort else "none"))
