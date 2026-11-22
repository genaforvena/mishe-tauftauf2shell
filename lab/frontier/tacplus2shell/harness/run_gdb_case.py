#!/usr/bin/env python3
"""Run one tac_plus-ng daemon under gdb on a plant-created loopback listener.

The daemon is launched by gdb as its child (ptrace_scope=1 requires a
descendant) with the plant-created 127.0.0.1 listening socket as fd 0.
No wildcard bind, no external address. Breakpoint output goes to --log;
client replies go to stdout. The whole process group is terminated after the
clients finish, so no daemon is left behind.
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


def wire(port, key, data, arg0, rest, rest_byte, ptype, sid="11223344", seq=1,
         user_len=0):
    cmd = [sys.executable, os.path.join(HERE, "wire.py"),
           "--port", str(port), "--host", "127.0.0.1", "--key", key,
           "--data", data, "--arg0", str(arg0), "--rest", str(rest),
           "--rest-byte", str(rest_byte), "--ptype", str(ptype),
           "--sid", sid, "--seq", str(seq), "--user-len", str(user_len)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return (r.stdout.strip() or r.stderr.strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--libdir", required=True)
    ap.add_argument("--cfg", default=os.path.join(HERE, "tac.cfg"))
    ap.add_argument("--port", type=int, default=4952)
    ap.add_argument("--log", required=True)
    ap.add_argument("--gdbcmd", required=True)
    ap.add_argument("--gdb", default="gdb")
    ap.add_argument("--start-wait", type=float, default=3.0)
    ap.add_argument("--end-wait", type=float, default=1.0)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--data", default="cmd=")
    ap.add_argument("--arg0", type=int, default=4)
    ap.add_argument("--rest", type=int, default=254)
    ap.add_argument("--rest-byte", type=int, default=0xFF)
    ap.add_argument("--ptype", type=int, default=2)
    ap.add_argument("--user-len", type=int, default=0)
    # Priming packet, sent first on the same connection path.
    ap.add_argument("--prime", action="store_true")
    ap.add_argument("--prime-data", default=None)
    ap.add_argument("--prime-arg0", type=int, default=4)
    ap.add_argument("--prime-rest", type=int, default=0)
    ap.add_argument("--prime-rest-byte", type=int, default=0)
    ap.add_argument("--prime-sid", default="11223344")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(16)
    srv.settimeout(1.0)

    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = args.libdir
    log = open(args.log, "wb")
    proc = subprocess.Popen(
        [args.gdb, "-q", "-batch", "-x", args.gdbcmd,
         "--args", args.bin, "-1", args.cfg],
        stdin=srv.fileno(), stdout=log, stderr=log,
        close_fds=False, pass_fds=(srv.fileno(),), env=env,
        cwd=ROOT, start_new_session=True,
    )
    time.sleep(args.start_wait)
    print(f"gdb_alive_at_trigger={proc.poll() is None}")
    if args.prime:
        prime_data = args.prime_data if args.prime_data is not None else args.data
        print("prime: " + wire(args.port, args.key, prime_data,
                               args.prime_arg0, args.prime_rest,
                               args.prime_rest_byte, args.ptype,
                               sid=args.prime_sid, seq=1))
        time.sleep(0.3)
    print("trigger: " + wire(args.port, args.key, args.data,
                             args.arg0, args.rest, args.rest_byte, args.ptype,
                             user_len=args.user_len))
    time.sleep(args.end_wait)
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        rc = proc.wait()
    log.flush()
    log.close()
    srv.close()
    print(f"gdb_rc={rc} log={args.log}")


if __name__ == "__main__":
    main()
