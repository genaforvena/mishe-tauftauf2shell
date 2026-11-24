#!/usr/bin/env python3
"""Run a GPGME verify driver while an HKP server on 127.0.0.1 serves one key.

The signed message is made with a throwaway lab key; the verifying GNUPGHOME
has no public key, so gpg auto-key-retrieves it over the loopback wire. No
external contact, no r5 claim.
"""
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
WIRE = os.path.join(HERE, "wireloop")
KEYS = os.path.join(HERE, "realgpg", "keys")
EVIDENCE = os.path.join(HERE, "realgpg", "evidence")
PORT = 11372


def make_handler(path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/pgp-keys")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass
    return Handler


def main():
    case, driver, key = sys.argv[1:4]
    os.makedirs(WIRE, exist_ok=True)
    os.makedirs(EVIDENCE, exist_ok=True)
    keyfile = os.path.join(KEYS, key + ".asc")
    genhome = os.path.join(KEYS, "gen-" + key)
    home = os.path.join(WIRE, "home-" + case)
    subprocess.run(["rm", "-rf", home], check=True)
    os.makedirs(home, mode=0o700)
    with open(os.path.join(home, "gpg.conf"), "w") as f:
        f.write("keyserver hkp://127.0.0.1:%d\nauto-key-retrieve\n" % PORT)

    signed = os.path.join(WIRE, case + ".msg")
    env = dict(os.environ, GNUPGHOME=genhome)
    with open(signed, "wb") as out:
        r = subprocess.run(["/usr/bin/gpg", "--batch", "--pinentry-mode",
                            "loopback", "--passphrase", "", "--clearsign"],
                           env=env, stdout=out, stderr=subprocess.PIPE)
    if r.returncode:
        print("sign failed", r.stderr.decode(errors="replace"), file=sys.stderr)
        return 2

    server = HTTPServer(("127.0.0.1", PORT), make_handler(keyfile))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with open(os.path.join(EVIDENCE, case + ".out"), "wb") as out:
            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
            rc = subprocess.run([os.path.join(HERE, driver), "/usr/bin/gpg",
                                 signed, home], env=env, stdout=out,
                                stderr=subprocess.STDOUT).returncode
    finally:
        server.shutdown()
    with open(os.path.join(EVIDENCE, case + ".rc"), "w") as f:
        f.write(str(rc) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
