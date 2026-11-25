#!/usr/bin/env python3
"""Check the crafted-RR write to hp_rand.i/hp_rand.j in the clang build.

The GDB log is read-only live state; hping's own debug stdout is the
independent observation.  Prediction reuses check_rng's RC4 step.
"""
import argparse
import re
import sys

import check_rng as base

REACH = 187

def addrs_from(path):
    """hping debug destinations, with kill-time prefix damage corroborated.

    One clean-archive replay ended with 'BUG: the dest address is ...'
    instead of 'DEBUG: ...'.  Accept that line only when the immediately
    following raw packet hex dump carries the same four destination
    octets; a bare prefix match is never enough.
    """
    rx = re.compile(r"^(?:DEBUG|BUG): the dest address is "
                    r"(\d+)\.(\d+)\.(\d+)\.(\d+)$")
    lines = open(path).read().splitlines()
    out = []
    for n, line in enumerate(lines):
        m = rx.match(line)
        if not m:
            continue
        addr = tuple(int(x) for x in m.groups())
        if line.startswith("DEBUG:"):
            out.append(addr)
            continue
        wire = lines[n + 1].split() if n + 1 < len(lines) else []
        if len(wire) >= 20:
            try:
                octets = tuple(int(x, 16) for x in wire[16:20])
            except ValueError:
                continue
            if octets == addr:
                out.append(addr)
    return out

def states_from(path):
    text = open(path).read()
    out = []
    for block in text.split("STATE hit")[1:]:
        def word(mark):
            m = re.search(mark + r"\n0x[0-9a-f]+[^\n]*:\s+0x([0-9a-f]+)", block)
            return int(m.group(1), 16) if m else None
        i, j = word("IP"), word("JP")
        sp = block.split("SP\n", 1)
        sbox = []
        if len(sp) == 2:
            for line in sp[1].splitlines():
                if ":" in line and re.match(r"0x[0-9a-f]+[^\n]*:", line.strip()):
                    sbox += [int(x, 16) for x in re.findall(
                        r"0x([0-9a-f]{2})(?![\da-f])", line.split(":", 1)[1])]
        if i is not None and j is not None and len(sbox) >= 256:
            out.append((i, j, bytes(sbox[:256])))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gdb_log")
    ap.add_argument("hping_out")
    ap.add_argument("--fill", type=int, default=0)
    ap.add_argument("--i0", type=int, default=32)
    ap.add_argument("--j0", type=int, default=128)
    ap.add_argument("--target-index", type=int, default=-1)
    ap.add_argument("--target-byte", type=int, default=0)
    ap.add_argument("--expect", choices=("attack", "baseline", "fixed"), default="attack")
    a = ap.parse_args()
    st = states_from(a.gdb_log)
    ad = addrs_from(a.hping_out)
    n = fails = 0

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
        print("IJ SUMMARY: %d checks run, INCOMPLETE" % n)
        return 1
    ok("GDB states %d, hping probe destinations %d" % (len(st), len(ad)))

    best = max(range(len(ad) - len(st) + 1),
               key=lambda k: sum(base.predicted(s)[3] == ad[p + k][3]
                                 for p, s in enumerate(st)))
    preds = [base.predicted(s)[3] for s in st]
    matched = sum(preds[p] == ad[p + best][3] for p in range(len(st)))
    if matched == len(st):
        ok("all %d probe low bytes predicted from logged live i/j/sbox" % len(st))
    else:
        bad("only %d/%d destinations predicted (alignment %d)" % (matched, len(st), best))

    filled = [p for p, (_, _, s) in enumerate(st)
              if sum(b == a.fill for b in s[:REACH]) >= REACH - 5]
    print("states with sbox[0..186] >=182/187 == 0x%02x: %s" % (a.fill, filled))
    print("first states (i,j): %s" %
          ", ".join("(%02x,%02x)" % (s[0], s[1]) for s in st[:6]))

    if a.expect in ("baseline", "fixed"):
        if not filled:
            ok("no constant-filled sbox state in the %s control" % a.expect)
        else:
            bad("%s control has a filled sbox state" % a.expect)
        tail = [ad[p + best + k][3] for p in filled for k in range(3)
                if p + best + k < len(ad)]
        hits = sum(b == a.fill for b in tail)
        if hits == 0:
            ok("zero post-attack destinations equal 0x%02x in the %s control" %
               (a.fill, a.expect))
        else:
            bad("%d/%d control destinations equal 0x%02x" % (hits, len(tail), a.fill))
        print("IJ SUMMARY: %d checks run, %s" % (n, "PASS" if fails == 0 else "FAIL"))
        return 0 if fails == 0 else 1

    if not filled:
        bad("no constant-filled sbox state after the crafted RR reply")
        print("IJ SUMMARY: %d checks run, FAIL" % n)
        return 1
    p = filled[0]
    if a.target_index >= 0 and st[p][2][a.target_index] != a.target_byte:
        bad("sbox[%d]=0x%02x at filled state, expected 0x%02x" %
            (a.target_index, st[p][2][a.target_index], a.target_byte))
    elif a.target_index >= 0:
        ok("sbox[%d]=0x%02x at filled state" % (a.target_index, a.target_byte))
    ok("state %d has sbox[0..186] filled with 0x%02x" % (p, a.fill))

    i_obs, j_obs, _ = st[p]
    i_set = [(a.i0 + 4 * k) & 0xFF for k in range(0, 6)]
    if i_obs in i_set:
        ok("live hp_rand.i=0x%02x equals the written i0=0x%02x advanced by k packets %s" %
           (i_obs, a.i0, i_set))
    else:
        bad("live hp_rand.i=0x%02x not in the written-index set %s" % (i_obs, i_set))
    # With a constant fill, hp_rand's si is the fill byte and j is fixed by
    # the written j0 while sbox[j] stays in the filled region.
    if j_obs == a.j0:
        ok("live hp_rand.j=0x%02x equals the written j0" % j_obs)
    elif a.fill == 0 and j_obs == (a.j0 + (i_obs - a.i0) * a.fill) & 0xFF:
        ok("live hp_rand.j consistent with written j0 and constant fill")
    else:
        bad("live hp_rand.j=0x%02x differs from written j0=0x%02x" % (j_obs, a.j0))

    chosen = a.target_byte if a.target_index >= 0 else a.fill
    tail = [ad[p + best + k][3] for k in range(len(ad) - p - best)]
    hits = sum(b == chosen for b in tail)
    print("observed destination low bytes after state %d: %s" %
          (p, " ".join("%02x" % b for b in tail)))
    if hits >= 2:
        ok("%d/%d post-attack probe destinations equal the chosen byte 0x%02x" %
           (hits, len(tail), chosen))
    else:
        bad("only %d/%d post-attack destinations equal 0x%02x" %
            (hits, len(tail), chosen))

    if p > 0 and base.predicted(st[p - 1])[3] != ad[p + best][3]:
        ok("unattacked counterfactual %02x != observed %02x" %
           (base.predicted(st[p - 1])[3], ad[p + best][3]))
    else:
        bad("no observable change from the pre-attack RC4 state")

    print("IJ SUMMARY: %d checks run, %s" % (n, "PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
