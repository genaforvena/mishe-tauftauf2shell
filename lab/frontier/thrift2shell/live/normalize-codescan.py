#!/usr/bin/env python3
"""Summarize gdb-codescan logs without addresses. Raw logs stay in results/."""
import re
import sys
from pathlib import Path

PATTERNS = [
    (re.compile(r"^SCAN_ANCHOR rbuf=0x[0-9a-f]+ sz=(\d+)$"), lambda m: "ANCHOR sz=" + m.group(1)),
    (re.compile(r"^SCAN_RBUF=0x[0-9a-f]+ NONZERO_QWORDS=(\d+) EXEC_QWORDS=(\d+) HEAP_QWORDS=(\d+)$"),
     lambda m: "WINDOW nonzero=%s exec=%s heap=%s" % m.groups()),
    (re.compile(r"^SCAN_CODE off=\+(\d+) val=0x[0-9a-f]+ map=(.*)$"),
     lambda m: "CODE off=+%s map=%s" % m.groups()),
    (re.compile(r"^SCAN_HEAP off=\+(\d+) val=0x[0-9a-f]+ map=(.*)$"),
     lambda m: "HEAP off=+%s map=%s" % m.groups()),
    (re.compile(r"^PROCESS_REACHED name=(\S+) seqid=(\d+)$"),
     lambda m: "PROCESS_REACHED name=%s seqid=%s" % m.groups()),
]

for path in (Path(p) for p in sys.argv[1:]):
    print("== " + path.stem)
    for line in path.read_text(errors="replace").splitlines():
        for rx, fmt in PATTERNS:
            m = rx.match(line)
            if m:
                print(fmt(m))
                break
