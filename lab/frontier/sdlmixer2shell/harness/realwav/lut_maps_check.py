#!/usr/bin/env python3
"""Test every saved-RIP value formable from the pinned WAV conversion LUT
against the mapped regions of the live no-SSP real-WAV driver.

The overflow at pinned decoder_wav.c:759 stores 32-bit float bit patterns from
MIX_alawToFloat / MIX_ulawToFloat.  A full saved-RIP overwrite is any ordered
pair of those words; a partial overwrite preserves the original high 32 bits
(0x00005555 for the observed PIE build, 0x00000000 for a hypothetical non-PIE
build) and takes one word as the low 32 bits.  Inputs: lut-dump.txt (512 gdb
words, already committed) and `gdb -batch -x gdb-map.cmd --args ...` output.
"""
import re
import sys
from pathlib import Path


def parse_lut(path):
    vals = []
    for line in Path(path).read_text().splitlines():
        if not line.startswith("0x") or "\t" not in line:
            continue
        for tok in line.split("\t")[1:]:
            tok = tok.strip()
            if re.fullmatch(r"0x[0-9a-fA-F]+", tok):
                vals.append(int(tok, 16))
    assert len(vals) == 512, f"expected 512 LUT words, got {len(vals)}"
    return vals


def parse_maps(text):
    ranges = []
    for line in text.splitlines():
        m = re.match(
            r"\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+"
            r"0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+(\S+)",
            line,
        )
        if m:
            ranges.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    assert ranges, "no mappings parsed"
    return ranges


def canonical_pair(hi, lo):
    """x86-64 canonical: address bits 63:47 all equal (hi[31:0], lo[15])."""
    sign = hi >> 31
    ones = 0xffff if sign else 0
    return (hi & 0xffff0000) == (ones << 16) and (hi & 0xffff) == ones \
        and ((lo >> 15) & 1) == sign


def hit(addr, ranges):
    for lo, hi, perms in ranges:
        if lo <= addr < hi:
            return f"0x{lo:x}-0x{hi:x} {perms}"
    return None


def main():
    vals = parse_lut(sys.argv[1])
    ranges = parse_maps(Path(sys.argv[2]).read_text())

    nz = [v for v in vals if v]
    print(f"mapped regions parsed: {len(ranges)}")
    print(f"LUT words: {len(vals)} zero: {len(vals) - len(nz)} "
          f"min nonzero: 0x{min(nz):08x} max: 0x{max(vals):08x}")
    print(f"words in non-PIE text window [0x400000,0x800000): "
          f"{sum(0x400000 <= v < 0x800000 for v in vals)}")

    pairs = [hi << 32 | lo for hi in vals for lo in vals
             if canonical_pair(hi, lo)]
    print(f"ordered 64-bit pairs: {len(vals) ** 2} canonical: {len(pairs)}")
    pair_hits = [(a, hit(a, ranges)) for a in pairs if hit(a, ranges)]
    print(f"canonical pairs hitting live mappings: {len(pair_hits)}")
    for addr, region in pair_hits[:8]:
        print(f"  pair 0x{addr:016x} -> {region}")

    total_hits = len(pair_hits)
    for name, high in (("pie", 0x00005555), ("nonpie", 0x00000000)):
        cands = [high << 32 | v for v in vals]
        hits = [(a, hit(a, ranges)) for a in cands if hit(a, ranges)]
        print(f"partial {name} (high 0x{high:08x}) hits: {len(hits)}")
        for addr, region in hits[:8]:
            print(f"  partial 0x{addr:016x} -> {region}")
        total_hits += len(hits)

    print("RESULT:", "NO_MAPPED_LUT_TARGET" if not total_hits else "REVIEW")
    return 0 if not total_hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
