#!/usr/bin/env python3
"""Check chosen destination octets under --rand-dest 127.x.x.x.

read-only GDB snapshots of hp_rand.i/j/rc4_sbox at
select_next_random_dest entry, plus hping's own debug stdout.  Each hp_rand()
call advances i four times; select_next_random_dest consumes the first byte
of one call per wildcard octet.  For 127.x.x.x the probe address is therefore
(127, seq[0], seq[4], seq[8]) computed from the snapshotted live state.
"""
import argparse

import check_ij
import check_rng


def predicted_full(state, wildcards):
    i, j, sbox = state
    seq = check_rng.sequence(i, j, sbox, 4 * wildcards)
    octets = [127, 0, 0, 0]
    for k in range(wildcards):
        octets[4 - wildcards + k] = seq[4 * k]
    return tuple(octets)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gdb_log")
    ap.add_argument("hping_out")
    ap.add_argument("--fill", type=int, default=1)
    ap.add_argument("--wildcards", type=int, choices=(1, 2, 3), default=3)
    ap.add_argument("--expect", choices=("attack", "baseline", "fixed"),
                    default="attack")
    a = ap.parse_args()
    st = check_ij.states_from(a.gdb_log)
    ad = check_ij.addrs_from(a.hping_out)
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
        print("MULTI SUMMARY: %d checks run, INCOMPLETE" % n)
        return 1
    ok("GDB states %d, hping probe destinations %d" % (len(st), len(ad)))
    best = max(range(len(ad) - len(st) + 1),
               key=lambda k: sum(predicted_full(s, a.wildcards) == ad[p + k]
                                 for p, s in enumerate(st)))
    preds = [predicted_full(s, a.wildcards) for s in st]
    matched = sum(preds[p] == ad[p + best] for p in range(len(st)))
    if matched == len(st):
        ok("all %d full probe destinations predicted from live i/j/sbox" % len(st))
    else:
        bad("only %d/%d full destinations predicted (alignment %d)" %
            (matched, len(st), best))

    filled = [p for p, (_, _, s) in enumerate(st)
              if sum(b == a.fill for b in s[:187]) >= 182]
    print("states with sbox[0..186] >=182/187 == 0x%02x: %s" % (a.fill, filled))
    if a.expect in ("baseline", "fixed"):
        if not filled:
            ok("no constant-filled sbox state in the %s control" % a.expect)
        else:
            bad("%s control has a filled sbox state" % a.expect)
        target = tuple([127] + [a.fill] * a.wildcards + [0] * (3 - a.wildcards))
        hits = sum(x == target for x in ad)
        if hits == 0:
            ok("zero destinations equal %s in the %s control" %
               (".".join(map(str, target)), a.expect))
        else:
            bad("%d/%d control destinations equal the chosen address" % (hits, len(ad)))
        print("MULTI SUMMARY: %d checks run, %s" %
              (n, "PASS" if fails == 0 else "FAIL"))
        return 0 if fails == 0 else 1

    if not filled:
        bad("no constant-filled sbox state after the crafted RR reply")
        print("MULTI SUMMARY: %d checks run, FAIL" % n)
        return 1
    p = filled[0]
    chosen = tuple([127] + [a.fill] * a.wildcards + [0] * (3 - a.wildcards))
    tail = ad[p + best:]
    hits = sum(x == chosen for x in tail)
    print("observed destinations after state %d: %s" %
          (p, " ".join(".".join(map(str, x)) for x in tail)))
    if hits >= 2:
        ok("%d/%d post-attack probes equal %s" %
           (hits, len(tail), ".".join(map(str, chosen))))
    else:
        bad("only %d/%d post-attack probes equal %s" %
            (hits, len(tail), ".".join(map(str, chosen))))
    if p > 0 and preds[p - 1] != ad[p + best]:
        ok("unattacked counterfactual %s != observed %s" %
           (".".join(map(str, preds[p - 1])), ".".join(map(str, ad[p + best]))))
    else:
        bad("no observable change from the pre-attack RC4 state")
    print("MULTI SUMMARY: %d checks run, %s" %
          (n, "PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
