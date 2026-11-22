#!/usr/bin/env python3
"""Assert every extracted slice is byte-identical to the pinned source."""
import pathlib
import sys

inc = pathlib.Path(sys.argv[1]).read_text()
src = pathlib.Path(sys.argv[2]).read_text()
markers = ("#define RTF_PREBUF ", "DWORD SwapDWord(", "BYTE *DecompressRTF(")
pos = [inc.index(m) for m in markers]
pos.append(len(inc.rstrip("\n")))
pieces = [inc[pos[i]:pos[i + 1]].rstrip("\n") for i in range(len(markers))]
missing = [p[:60] for p in pieces if p not in src]
if missing:
    print("VERBATIM FAIL " + repr(missing))
    sys.exit(1)
print("VERBATIM OK slices=%d pin=%s" % (len(pieces), sys.argv[2]))
