#!/usr/bin/env python3
"""Run one tac_plus-ng daemon case on a plant-started 127.0.0.1 listener.

The daemon is launched inetd-style: a loopback-only listening socket is passed
as fd 0, so no wildcard bind and no external interface is ever touched. stderr
(where ASan writes) is captured to a per-case log. The daemon is killed after
the client finishes; its exit status and the log are reported.
"""
import argparse
import os
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--cfg", default=os.path.join(HERE, "tac.cfg"))
    ap.add_argument("--port", type=int, default=4949)
    ap.add_argument("--log", required=True)
    ap.add_argument("--data", default="cmd=")
    ap.add_argument("--arg0", type=int, default=4)
    ap.add_argument("--rest", type=int, default=254)
    ap.add_argument("--rest-byte", type=int, default=0xFF)
    ap.add_argument("--ptype", type=int, default=2)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--start-wait", type=float, default=2.0)
    ap.add_argument("--asan", default="detect_leaks=0:abort_on_error=1")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(16)
    srv.settimeout(1.0)

    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = os.path.join(
        ROOT, "src", "build", "linux-6.8.0-149-generic-x86_64", "mavis")
    env["ASAN_OPTIONS"] = args.asan

    log = open(args.log, "wb")
    proc = subprocess.Popen(
        [args.bin, "-1", args.cfg],
        stdin=srv.fileno(), stdout=log, stderr=log,
        close_fds=False, pass_fds=(srv.fileno(),), env=env,
        cwd=ROOT,
    )
    time.sleep(args.start_wait)
    alive = proc.poll() is None

    replies = []
    for _ in range(args.repeat):
        cmd = [sys.executable, os.path.join(HERE, "wire.py"),
               "--port", str(args.port), "--host", "127.0.0.1",
               "--key", args.key, "--data", args.data,
               "--arg0", str(args.arg0), "--rest", str(args.rest),
               "--rest-byte", str(args.rest_byte), "--ptype", str(args.ptype)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        replies.append(r.stdout.strip() or r.stderr.strip())

    time.sleep(0.5)
    proc.send_signal(signal.SIGTERM)
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = proc.wait()
    log.flush()
    log.close()
    srv.close()

    print(f"daemon_alive_at_trigger={alive} daemon_rc={rc}")
    for i, r in enumerate(replies):
        print(f"client[{i}]: {r}")
    print(f"log={args.log}")


if __name__ == "__main__":
    main()
