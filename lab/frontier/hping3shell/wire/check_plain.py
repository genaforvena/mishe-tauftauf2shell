#!/usr/bin/env python3
"""Verify the plain-build wire result from a GDB dump of old_rr.

attack: chosen ICMP payload bytes at old_rr+46..109 and at old_rr+64..109,
        the latter labeled <rc4_sbox> by GDB and by nm in the live build.
baseline (NO_INJECT=1): rc4_sbox[0..45] must NOT equal the attack pattern.
The first ~46 bytes of old_rr are later rewritten by kernel-generated RR
replies (i<=11), so they are deliberately not asserted.
"""
import re
import sys

BYTE = re.compile(r"0x([0-9a-fA-F]{2})(?![0-9a-fA-F])")
PAY_MARKER = list(range(0x01, 0x41))
SBOX_ATTACK = list(range(0x13, 0x41))


def parse(path):
    lines, out = [], []
    with open(path, errors="replace") as f:
        for line in f:
            if not line.lstrip().startswith("0x"):
                continue
            vals = [int(b, 16) for b in BYTE.findall(line)]
            if not vals:
                continue
            lines.append(line.rstrip("\n"))
            out.extend(vals)
    return lines, out


def main():
    args = sys.argv[1:]
    if args and args[0] == "baseline":
        baseline, args = True, args[1:]
    else:
        baseline = False
    if len(args) != 1:
        print("usage: check_plain.py [baseline] GDB_OUT")
        return 2
    lines, raw = parse(args[0])
    n = 0
    def chk(label, ok):
        nonlocal n
        n += 1
        print("PASS %02d: %s" % (n, label) if ok else "FAIL %02d: %s" % (n, label))
        return ok
    good = True
    good &= chk("gdb dumped >=120 bytes at old_rr", len(raw) >= 120)
    if len(raw) < 120:
        return 1
    if baseline:
        print("baseline rc4_sbox[0..45] =", " ".join("%02x" % b for b in raw[64:110]))
        good &= chk("baseline rc4_sbox[0..45] is not the attack pattern",
                    raw[64:110] != SBOX_ATTACK)
        good &= chk("baseline gdb still labels old_rr+64 as <rc4_sbox>",
                    len(lines) > 8 and "<rc4_sbox>" in lines[8])
        print("PLAIN SUMMARY: %d checks, %s" % (n, "PASS" if good else "FAIL"))
        return 0 if good else 1
    good &= chk("old_rr[46..109] = 64 unique ICMP payload bytes", raw[46:110] == PAY_MARKER)
    good &= chk("rc4_sbox[0..45] = payload bytes 18..63 (0x13..0x40)",
                raw[64:110] == SBOX_ATTACK)
    good &= chk("gdb labels old_rr+64 as <rc4_sbox> in the live process",
                len(lines) > 8 and "<rc4_sbox>" in lines[8])
    print("NOTE: old_rr[0..45] later rewritten by kernel param-problem RR (i<=11);")
    print("      deeper chosen bytes persist because later writes are shorter.")
    print("PLAIN SUMMARY: %d checks, %s" % (n, "PASS" if good else "FAIL"))
    return 0 if good else 1


if __name__ == "__main__":
    raise SystemExit(main())
