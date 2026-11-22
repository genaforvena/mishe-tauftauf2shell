#!/usr/bin/env python3
"""Relocate an extracted clean-HEAD archive for the wire replay.

The committed leak configs carry the original lab's absolute path prefix, and
the ftpd.passwd/ftpd.group test files are deliberately untracked.  Run this
once on an extracted `git archive HEAD lab/frontier/proftpd2shell` tree before
starting a daemon from it.  No live-tree file is read or modified; the test
account is regenerated with the fixed lab hash (password `labpass`).

Usage: setup-clean-replay.py ARCHIVE_ROOT
"""
import os
import sys

OLD = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/proftpd2shell/wire"
PASSWD = "labuser:$1$yefAU54S$6LXk5rWtfRjtA421VSZg./:1000:1000::{home}:/bin/false\n"
GROUP = "mesh-home:x:1000:\n"
CONFIGS = ("proftpd-leak.conf", "proftpd-prelogin-leak.conf")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = os.path.abspath(sys.argv[1])
    wire = os.path.join(root, "lab/frontier/proftpd2shell/wire")
    etc = os.path.join(wire, "etc")
    for name in CONFIGS:
        path = os.path.join(etc, name)
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        if OLD not in text:
            sys.exit("unexpected config prefix in " + path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.replace(OLD, wire))
    with open(os.path.join(etc, "ftpd.passwd"), "w", encoding="utf-8") as f:
        f.write(PASSWD.format(home=os.path.join(wire, "home")))
    with open(os.path.join(etc, "ftpd.group"), "w", encoding="utf-8") as f:
        f.write(GROUP)
    for name in ("log", "run", "evidence", "home"):
        os.makedirs(os.path.join(wire, name), exist_ok=True)
    print("RELOCATED", wire)


if __name__ == "__main__":
    main()
