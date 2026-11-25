#!/usr/bin/env python3
"""Check three DISTINCT chosen destination octets under --rand-dest 127.x.x.x.

Read-only GDB snapshots of hp_rand.i/j/rc4_sbox at
select_next_random_dest entry, plus hping's own debug stdout.  The crafted
RR reply writes an arbitrary 187-byte sbox pattern; check_rng.sequence()
with the injected i0/j0 predicts the first byte of each of the first three
hp_rand() calls, which become the last three octets of the probe address.
"""
import argparse

import check_ij
import check_multioctet
import check_rng


def read_pattern(path):
    text = "".join(open(path).read().split())
    p = bytes.fromhex(text)
    if len(p) != 187:
        raise ValueError("pattern must be 187 bytes")
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gdb_log")
    ap.add_argument("hping_out")
    ap.add_argument("--pattern-file", required=True)
    ap.add_argument("--i0", type=int, default=32)
    ap.add_argument("--j0", type=int, default=16)
    ap.add_argument("--expect", choices=("attack", "baseline", "fixed"),
                    default="attack")
    ap.add_argument("--min-hits", type=int, default=1)
    a = ap.parse_args()
    pattern = read_pattern(a.pattern_file)
    full_sbox = bytes(pattern) + bytes(256 - len(pattern))
    seq = check_rng.sequence(a.i0, a.j0, full_sbox, 12)
    chosen = (127, seq[0], seq[4], seq[8])
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
        bad("too few aligned observations: states=%d addresses=%d" %
            (len(st), len(ad)))
        print("PATTERN SUMMARY: %d checks run, INCOMPLETE" % n)
        return 1
    ok("GDB states %d, hping probe destinations %d" % (len(st), len(ad)))
    best = max(range(len(ad) - len(st) + 1),
               key=lambda k: sum(check_multioctet.predicted_full(s, 3) == ad[p + k]
                                 for p, s in enumerate(st)))
    preds = [check_multioctet.predicted_full(s, 3) for s in st]
    matched = sum(preds[p] == ad[p + best] for p in range(len(st)))
    if matched == len(st):
        ok("all %d full probe destinations predicted from live i/j/sbox" % len(st))
    else:
        bad("only %d/%d full destinations predicted (alignment %d)" %
            (matched, len(st), best))

    filled = [p for p, (_, _, s) in enumerate(st)
              if sum(x == y for x, y in zip(s[:187], pattern)) >= 182]
    print("states with sbox[0..186] matching the 187-byte pattern >=182/187: %s" %
          filled)
    if a.expect in ("baseline", "fixed"):
        if not filled:
            ok("no injected sbox pattern in the control build")
        else:
            bad("injected sbox pattern present in the control build")
        hits = sum(x == chosen for x in ad)
        if hits == 0:
            ok("zero chosen-address probes in the control build")
        else:
            bad("%d/%d control probes equal the chosen address" % (hits, len(ad)))
        print("PATTERN SUMMARY: %d checks run, %s" %
              (n, "PASS" if fails == 0 else "FAIL"))
        return 0 if fails == 0 else 1

    if not filled:
        bad("no injected sbox pattern state after the crafted RR reply")
        print("PATTERN SUMMARY: %d checks run, FAIL" % n)
        return 1
    if len(set(chosen[1:])) == 3:
        ok("chosen octets are distinct: %s" % ".".join(map(str, chosen)))
    else:
        bad("chosen octets are not distinct: %s" % ".".join(map(str, chosen)))
    p = filled[0]
    tail = ad[p + best:]
    hits = sum(x == chosen for x in tail)
    print("observed destinations after state %d: %s" %
          (p, " ".join(".".join(map(str, x)) for x in tail)))
    if hits >= a.min_hits:
        ok("%d/%d post-attack probes equal %s" %
           (hits, len(tail), ".".join(map(str, chosen))))
    else:
        bad("only %d/%d post-attack probes equal %s (need %d)" %
            (hits, len(tail), ".".join(map(str, chosen)), a.min_hits))
    if p > 0 and preds[p - 1] != ad[p + best]:
        ok("unattacked counterfactual %s != observed %s" %
           (".".join(map(str, preds[p - 1])), ".".join(map(str, ad[p + best]))))
    else:
        bad("no observable change from the pre-attack RC4 state")
    print("PATTERN SUMMARY: %d checks run, %s" %
          (n, "PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
