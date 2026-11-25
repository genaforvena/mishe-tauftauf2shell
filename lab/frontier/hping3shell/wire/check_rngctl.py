#!/usr/bin/env python3
"""Check attacker-chosen RNG output control from the long crafted RR reply.

Reads the read-only GDB state log and hping3 debug stdout produced by
rngctl-proof.sh.  Reuses check_rng.py's state/address parsing and RC4 step so
the alignment and prediction are the same as the W5 proof.
"""
import argparse
import sys

import check_rng as base

REACH = 187  # rc4_sbox[0..186] is the part a 251-byte memcpy can reach


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gdb_log")
    ap.add_argument("hping_out")
    ap.add_argument("--fill", type=int, default=0x20)
    ap.add_argument("--expect", choices=("attack", "baseline"), default="attack")
    a = ap.parse_args()
    st = base.states_from(a.gdb_log)
    ad = base.addrs_from(a.hping_out)
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
        print("RNGCTL SUMMARY: %d checks run, INCOMPLETE" % n)
        return 1
    ok("GDB states %d, hping probe destinations %d" % (len(st), len(ad)))

    best = max(range(len(ad) - len(st) + 1),
               key=lambda k: sum(base.predicted(s) == ad[p + k] for p, s in enumerate(st)))
    preds = [base.predicted(s) for s in st]
    matched = sum(preds[p] == ad[p + best] for p in range(len(st)))
    if matched == len(st):
        ok("all %d probe destinations predicted from logged live sbox/i/j" % len(st))
    else:
        bad("only %d/%d destinations predicted (alignment %d)" % (matched, len(st), best))

    steps = [(st[p + 1][0] - st[p][0]) & 0xFF for p in range(len(st) - 1)]
    if all(x == base.CALLS_PER_PACKET for x in steps):
        ok("i advances by %d hp_rand calls per packet" % base.CALLS_PER_PACKET)
    else:
        bad("unexpected hp_rand call count per packet: %s" % steps[:8])

    filled = [p for p, (_, _, s) in enumerate(st)
              if sum(b == a.fill for b in s[:REACH]) >= REACH - 5]
    print("states with sbox[0..186] >=182/187 equal to 0x%02x: %s" % (a.fill, filled))
    if a.expect == "baseline":
        if not filled:
            ok("no constant-filled sbox state in the baseline")
        else:
            bad("baseline unexpectedly has constant-filled sbox at %s" % filled)
        print("RNGCTL SUMMARY: %d checks run, %s" %
              (n, "PASS" if fails == 0 else "FAIL"))
        return 0 if fails == 0 else 1

    if not filled:
        bad("no constant-filled sbox state after the crafted RR reply")
        print("RNGCTL SUMMARY: %d checks run, FAIL" % n)
        return 1
    p = filled[0]
    ok("post-attack state %d has sbox[0..186] filled with 0x%02x" % (p, a.fill))

    tail = [ad[p + best + k][3] for k in range(len(ad) - p - best)]
    hits = sum(b == a.fill for b in tail)
    print("observed destination low bytes after state %d: %s" %
          (p, " ".join("%02x" % b for b in tail)))
    if hits >= 2:
        ok("%d/%d post-attack probe destinations equal the chosen byte 0x%02x" %
           (hits, len(tail), a.fill))
    else:
        bad("only %d/%d post-attack destinations equal 0x%02x" % (hits, len(tail), a.fill))

    if p > 0 and base.predicted(st[p - 1], base.CALLS_PER_PACKET) != ad[p + best]:
        ok("unattacked counterfactual %s != observed %s" %
           (base.fmt(base.predicted(st[p - 1], base.CALLS_PER_PACKET)),
            base.fmt(ad[p + best])))
    else:
        bad("no observable change from the pre-attack RC4 state")

    print("RNGCTL SUMMARY: %d checks run, %s" %
          (n, "PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
