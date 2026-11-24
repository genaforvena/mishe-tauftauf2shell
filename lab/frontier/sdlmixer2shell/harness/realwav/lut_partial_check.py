#!/usr/bin/env python3
"""Check whether any LUT float bit pattern could serve as the low 32 bits of a
partially overwritten saved RIP whose high 32 bits stay 0x00005555 (PIE).

The no-SSP frame's original saved RIP is 0x0000555555560a60; a length-142
FetchXLaw call replaces only its low four bytes with MIX_alawToFloat[byte].
For the result to stay mapped in the PIE the low word must land in the binary's
executable window (~0x55554000..0x55560000 here), which requires high byte
0x55. Input: the `x/256xw &MIX_alawToFloat` / `&MIX_ulawToFloat` gdb dump.
"""
import re
import sys
from pathlib import Path

# PIE text low-32 window observed in the no-SSP driver (conservative bound).
LO, HI = 0x55554000, 0x55560000

def parse(path):
    vals = []
    for line in Path(path).read_text().splitlines():
        if not line.startswith("0x") or "\t" not in line:
            continue
        for tok in line.split("\t")[1:]:
            tok = tok.strip()
            if re.fullmatch(r"0x[0-9a-fA-F]+", tok):
                vals.append(int(tok, 16))
    return vals

def main():
    vals = parse(sys.argv[1])
    assert len(vals) == 512, f"expected 512 LUT words, got {len(vals)}"
    inwin = [v for v in vals if LO <= v <= HI]
    hi55 = [v for v in vals if (v >> 24) == 0x55]
    print(f"LUT words checked: {len(vals)}")
    print(f"window [0x{LO:08x},0x{HI:08x}] hits: {len(inwin)}")
    print(f"high-byte-0x55 words: {len(hi55)}")
    print("RESULT:", "NO_MAPPED_PARTIAL_TARGET" if not inwin and not hi55 else "REVIEW")
    return 0 if not inwin and not hi55 else 1

if __name__ == "__main__":
    raise SystemExit(main())
