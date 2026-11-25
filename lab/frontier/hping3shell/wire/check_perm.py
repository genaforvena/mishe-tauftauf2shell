#!/usr/bin/env python3
"""Check a crafted RR reply's permutation write to rc4_sbox[0..186].

Reuses check_rng.py's proven four-calls-per-packet RC4 model.  The checker
asserts (1) all observed full destinations follow the live GDB state,
(2) a post-attack state holds a reply-chosen permutation across all 187
reachable sbox bytes, and (3) the first output byte after the permutation
is the reply-chosen value S[index], with the unattacked counterfactual
different.  It does NOT claim full-IP control: hping's --rand-dest template
hardcodes the other octets to 127.0.0.x.
"""
import argparse

import check_rng as base

REACH = 187
PERMS = {
    "inc": lambda n: (n + 1) & 0xFF,
    "dec": lambda n: (n - 1) & 0xFF,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gdb_log")
    ap.add_argument("hping_out")
    ap.add_argument("--mode", choices=("inc", "dec"), required=True)
    ap.add_argument("--expect", choices=("attack", "baseline", "fixed"), default="attack")
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
        print("PERM SUMMARY: %d checks run, INCOMPLETE" % n)
        return 1
    ok("GDB states %d, hping probe destinations %d" % (len(st), len(ad)))

    # check_rng.py predicts the destination from state p after CALLS_PER_PACKET
    # further hp_rand calls; its alignment search is the established model.
    preds = [base.predicted(s) for s in st]
    best = max(range(len(ad) - len(st) + 1),
               key=lambda k: sum(preds[p] == ad[p + k] for p, s in enumerate(st)))
    matched = sum(preds[p] == ad[p + best] for p in range(len(st)))
    if matched == len(st):
        ok("all %d full probe destinations predicted from logged live sbox/i/j" % len(st))
    else:
        bad("only %d/%d probe destinations predicted (alignment %d)" % (matched, len(st), best))

    perm = PERMS[a.mode]
    tainted = [p for p, (_, _, s) in enumerate(st)
               if sum(s[k] == perm(k) for k in range(REACH)) >= REACH - 5]
    print("states with sbox[0..186] >=182/187 equal to %s permutation: %s" % (a.mode, tainted))
    if a.expect in ("baseline", "fixed"):
        if not tainted:
            ok("no permutation-filled sbox state in the %s control" % a.expect)
        else:
            bad("%s unexpectedly has a permutation-filled sbox at %s" % (a.expect, tainted))
        print("PERM SUMMARY: %d checks run, %s" % (n, "PASS" if fails == 0 else "FAIL"))
        return 0 if fails == 0 else 1
    if not tainted:
        bad("no permutation-filled sbox state after the crafted RR reply")
        print("PERM SUMMARY: %d checks run, FAIL" % n)
        return 1

    p = tainted[0]
    ok("post-attack state %d has sbox[0..186] holding the %s permutation" % (p, a.mode))
    i, j, sbox = st[p]
    si = sbox[(i + 1) & 0xFF]
    j1 = (j + si) & 0xFF
    sj = sbox[j1]
    k = (si + sj) & 0xFF
    chosen = sbox[k]
    expected = perm(k)
    print("state %d: i=%d j=%d; first output index=%d, live S[k]=%d, reply schedule=%d" %
          (p, i, j, k, chosen, expected))
    if chosen == expected:
        ok("first post-attack output byte %d equals the reply-chosen permutation value" % chosen)
    else:
        bad("output byte %d != reply schedule %d" % (chosen, expected))

    # The destination at state p's alignment is the first byte after the
    # permutation; check_rng's alignment put it at ad[p + best].
    if p + best < len(ad):
        observed = ad[p + best][3]
        if observed == chosen:
            ok("observed destination low byte %d equals the chosen byte" % observed)
        else:
            bad("observed low byte %d != chosen byte %d" % (observed, chosen))
        if p > 0:
            counter = base.predicted(st[p - 1], base.CALLS_PER_PACKET)[3]
            if counter != observed:
                ok("unattacked counterfactual low byte %d != observed %d" % (counter, observed))
            else:
                bad("no observable change from pre-attack RC4 state")
    else:
        ok("no post-attack destination at the tainted state's alignment")

    print("CEILING: only the 127.0.0.x low byte is wire-visible; the other "
          "permutation bytes are in RC4 state but not emitted by --rand-dest.")
    print("PERM SUMMARY: %d checks run, %s" % (n, "PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
