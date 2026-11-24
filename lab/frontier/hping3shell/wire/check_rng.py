#!/usr/bin/env python3
"""Check whether the crafted RR write changes hp_rand()'s live output.

Reads a GDB state log and hping3's debug stdout from rng-proof.sh.  At each
random-address selection the log records i.1, j.0 and 256 bytes of random.c's
rc4_sbox (the object immediately after old_rr).  In this build hping is run
with `--rand-dest 127.0.0.x`: four hp_rand() calls per packet, and the low
byte of the next probe destination is the first call's output byte.
"""
import argparse
import re
import sys

MARKER = bytes(range(0x13, 0x41))  # sbox[0..45] after the crafted RR write
CALLS_PER_PACKET = 4


def states_from(path):
    text = open(path).read()
    out = []
    for block in text.split("STATE hit")[1:]:
        i = re.search(r"0x[0-9a-f]+ <i\.1>:\s+0x([0-9a-f]+)", block)
        j = re.search(r"0x[0-9a-f]+ <j\.0>:\s+0x([0-9a-f]+)", block)
        if not i or not j:
            continue
        sbox = []
        for line in block.splitlines():
            if "<rc4_sbox" in line and ":" in line:
                sbox += [int(x, 16) for x in
                         re.findall(r"0x([0-9a-f]{2})(?![\da-f])", line.split(":", 1)[1])]
        out.append((int(i.group(1), 16), int(j.group(1), 16), bytes(sbox)))
    return out


def addrs_from(path):
    text = open(path).read()
    return [tuple(int(x) for x in m) for m in re.findall(
        r"DEBUG: the dest address is (\d+)\.(\d+)\.(\d+)\.(\d+)", text)]


def sequence(i, j, sbox, count):
    s = bytearray(sbox)
    vals = []
    for _ in range(count):
        i = (i + 1) & 0xFF
        si = s[i]
        j = (j + si) & 0xFF
        sj = s[j]
        s[i] = sj
        s[j] = si
        vals.append(s[(si + sj) & 0xFF])
    return vals


def predicted(state, offset=0):
    i, j, sbox = state
    vals = sequence(i, j, sbox, offset + 1)
    return (127, 0, 0, vals[offset])


def fmt(a):
    return ".".join(str(x) for x in a)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gdb_log")
    ap.add_argument("hping_out")
    a = ap.parse_args()
    st = states_from(a.gdb_log)
    ad = addrs_from(a.hping_out)
    n = 0
    fails = 0

    def ok(msg):
        nonlocal n
        n += 1
        print("PASS %02d: %s" % (n, msg))

    def bad(msg):
        nonlocal n, fails
        n += 1
        fails += 1
        print("FAIL %02d: %s" % (n, msg))

    if len(st) < 3 or len(ad) < len(st):
        bad("too few aligned observations: states=%d addresses=%d" % (len(st), len(ad)))
        print("RNG SUMMARY: %d checks run, INCOMPLETE" % n)
        return 1
    ok("GDB states %d, hping probe destinations %d" % (len(st), len(ad)))

    # GDB attaches a few packets after hping starts; find the alignment offset.
    best = max(range(len(ad) - len(st) + 1),
               key=lambda k: sum(predicted(s) == ad[p + k] for p, s in enumerate(st)))
    preds = [predicted(s) for s in st]
    matched = sum(preds[p] == ad[p + best] for p in range(len(st)))
    if matched == len(st):
        ok("all %d probe destinations predicted from logged live sbox/i/j" % len(st))
    else:
        bad("only %d/%d destinations predicted (alignment %d)" %
            (matched, len(st), best))

    steps = [(st[p + 1][0] - st[p][0]) & 0xFF for p in range(len(st) - 1)]
    if all(x == CALLS_PER_PACKET for x in steps):
        ok("i advances by %d hp_rand call per packet" % CALLS_PER_PACKET)
    else:
        bad("unexpected hp_rand call count per packet: %s" % steps[:8])

    tainted = [p for p, (_, _, s) in enumerate(st) if s[:46] == MARKER]
    if not tainted:
        ok("no crafted RR marker in sbox[0..45] (baseline)")
        print("RNG SUMMARY: %d checks run, %s" %
              (n, "PASS" if fails == 0 else "FAIL"))
        return 0 if fails == 0 else 1
    p = tainted[0]
    ok("post-attack state %d carries the crafted RR marker in sbox[0..45]" % p)

    actual = ad[p + best]
    if preds[p] == actual:
        ok("observed probe destination %s matches prediction from overwritten sbox" %
           fmt(actual))
    else:
        bad("observed destination %s != prediction %s" %
            (fmt(actual), fmt(preds[p])))

    if p > 0:
        counter = predicted(st[p - 1], CALLS_PER_PACKET)
        if counter != actual:
            ok("unattacked counterfactual %s != observed %s" %
               (fmt(counter), fmt(actual)))
        else:
            bad("no observable change: counterfactual %s == observed %s" %
                (fmt(counter), fmt(actual)))
    else:
        bad("no pre-attack state before the tainted one")

    print("RNG SUMMARY: %d checks run, %s" %
          (n, "PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
