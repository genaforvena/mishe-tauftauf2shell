#!/usr/bin/env python3
"""Audit regexp stale-buffer link words against observed heap addresses.

Reads gitignored evidence produced by ruby2shell-regexp-notes-wire.py with
RUBY2SHELL_REGEXP_TRACE=1 (and optional REGTRACE_DUMP_*). No runtime is started.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "lab/build/evidence"
UNICODE_CAP = 0x10FFFF


def heap_bases() -> list[int]:
    bases: list[int] = []
    for path in sorted(EV.glob("regexp-*.maps")):
        for line in path.read_text(errors="replace").splitlines():
            if "[heap]" not in line:
                continue
            start = line.split("-", 1)[0]
            try:
                bases.append(int(start, 16))
            except ValueError:
                continue
    return bases


def classify(value: int, high32: set[int]) -> str:
    if value == 0:
        return "zero"
    if (value >> 32) in high32:
        return "heap-high32"
    if value <= UNICODE_CAP:
        return "one-codepoint"
    if (value >> 32) <= UNICODE_CAP and (value & 0xFFFFFFFF) <= UNICODE_CAP:
        return "two-codepoints"
    return "other"


def link_words(log: Path, high32: set[int]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for line in log.read_text(errors="replace").splitlines():
        fields = line.split()
        if not fields or fields[0] not in ("F", "A"):
            continue
        for word in fields[4:6]:
            if len(word) != 16 or any(c not in "0123456789abcdef" for c in word):
                continue
            counts[classify(int(word, 16), high32)] += 1
    return counts


def main() -> int:
    logs = [EV / name for name in sys.argv[1:]] or sorted(EV.glob("regexp-*.server.log"))
    bases = heap_bases()
    if not bases:
        raise SystemExit(f"no regexp-*.maps heap rows in {EV}")
    low32 = [base & 0xFFFFFFFF for base in bases]
    high32 = {base >> 32 for base in bases}
    print(f"heap_rows={len(bases)} min_low32=0x{min(low32):x} "
          f"low32_under_unicode_cap={sum(v <= UNICODE_CAP for v in low32)}")
    for log in logs:
        if not log.is_file():
            print(f"{log.name}: missing")
            continue
        counts = link_words(log, high32)
        print(f"{log.name}: " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
