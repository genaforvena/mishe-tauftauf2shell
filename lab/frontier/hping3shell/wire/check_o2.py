#!/usr/bin/env python3
"""Check the -O2 build outcome of the crafted RR reply.

At -O2 GCC 13 on this host defaults to _FORTIFY_SOURCE=3, and
display_ipopt()'s memcpy becomes __memcpy_chk(dst, src, n, 40).  The crafted
255-byte RR reply therefore aborts in glibc BEFORE any global is written.
Modes: attack expects the abort and no overwritten RC4 state; baseline/fixed
expect a clean run with no chosen state.
"""
import argparse
import re

J, I, FILL, REACH = 7, 5, 0x41, 155
ABORT = "buffer overflow detected"


def states_from(path):
    text = open(path).read()
    out = []
    for block in text.split("STATE hit")[1:]:
        words = re.findall(r":\s+0x([0-9a-f]+)", block)
        sbox = []
        for line in block.splitlines():
            if "<rc4_sbox" in line:
                vals = re.findall(r"0x([0-9a-f]{2})(?![\da-f])", line)
                sbox += [int(x, 16) for x in vals]
        if len(words) < 2 or len(sbox) < 256:
            continue
        out.append((int(words[0], 16), int(words[1], 16), bytes(sbox[:256])))
    return out


def addrs_from(path):
    return [tuple(int(x) for x in m) for m in re.findall(
        r"DEBUG: the dest address is (\d+)\.(\d+)\.(\d+)\.(\d+)",
        open(path).read())]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gdb_log")
    ap.add_argument("hping_out")
    ap.add_argument("--expect", choices=("attack", "baseline", "fixed"),
                    default="attack")
    a = ap.parse_args()
    st = states_from(a.gdb_log)
    run = open(a.hping_out).read()
    ad = addrs_from(a.hping_out)
    n = fails = 0

    def ok(msg):
        nonlocal n
        n += 1
        print("PASS %02d: %s" % (n, msg))

    def fail(msg):
        nonlocal n, fails
        n += 1
        fails += 1
        print("FAIL %02d: %s" % (n, msg))

    ok("GDB states %d, probe destinations %d" % (len(st), len(ad)))
    chosen = [p for p, (i, j, s) in enumerate(st)
              if i == I and j == J and sum(b == FILL for b in s[:REACH]) == REACH]
    if not chosen:
        ok("no GDB state carries the crafted i/j/fill")
    else:
        fail("crafted state reached the RNG at %s" % chosen[:3])
    aborted = ABORT in run
    if a.expect == "attack":
        if aborted:
            ok("run aborted in glibc: buffer overflow detected")
        else:
            fail("no fortify abort in the attacked -O2 process")
    else:
        if aborted:
            fail("clean control aborted in glibc")
        else:
            ok("clean control did not abort")
        if len(ad) >= 20:
            ok("clean control printed %d probe destinations" % len(ad))
        else:
            fail("only %d probe destinations in clean control" % len(ad))
    print("O2 FORTIFY SUMMARY: %d checks, %s" %
          (n, "PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
