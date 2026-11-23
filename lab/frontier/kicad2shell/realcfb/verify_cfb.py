#!/usr/bin/env python3
"""Independent read-back proof that each fixture is a real MS-CFB container
with a FileHeader stream carrying the crafted bytes. Uses olefile, not the
lab's own C++ reader."""
import glob
import os
import sys

import olefile

EXPECT = {
    "baseline": b"SIZE1=10",
    "attackz": b"SIZEZ=84215045",
    "attackneg": b"SIZE-1=84215045",
    "attackfar": b"SIZE-1=84215045",
}

ok = True
for path in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "fixtures", "*.SchLib"))):
    name = os.path.basename(path).replace("FileHeader-", "").replace(".SchLib", "")
    valid = olefile.isOleFile(path)
    o = olefile.OleFileIO(path)
    streams = o.listdir()
    data = o.openstream("FileHeader").read()
    o.close()
    good = (valid and ["FileHeader"] in streams and EXPECT[name] in data)
    ok = ok and good
    print("%-10s olefile=%s streams=%s size=%d key_ok=%s %s"
          % (name, valid, streams, len(data), EXPECT[name] in data,
             "PASS" if good else "FAIL"))

print("ALL_FIXTURES_OK" if ok else "FIXTURE_FAILURE")
sys.exit(0 if ok else 1)
