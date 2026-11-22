#!/usr/bin/env python3
"""Launch plain daemon under gdb on a plant-created 127.0.0.1 listener, then
run one client that sends prime+trigger on the SAME connection. No off-loopback
traffic; gdb is the parent (ptrace_scope=1).
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
    ap.add_argument("--libdir", required=True)
    ap.add_argument("--cfg", default=os.path.join(HERE, "tac.cfg"))
    ap.add_argument("--port", type=int, default=4974)
    ap.add_argument("--log", required=True)
    ap.add_argument("--gdbcmd", required=True)
    ap.add_argument("--client", default="wire2.py")
    ap.add_argument("--prime-data", default=None)
    ap.add_argument("--prime-arg0", type=int, default=8)
    ap.add_argument("--prime-rest", type=int, default=254)
    ap.add_argument("--prime-rest-byte", type=int, default=8)
    ap.add_argument("--data", default="cmd=AAAAcmd=BBBBcmd=CCCCcmd=DDDDcmd=EEEEcmd=FFFFcmd=GGGGcmd=HHHH")
    ap.add_argument("--arg0", type=int, default=8)
    ap.add_argument("--rest", type=int, default=19)
    ap.add_argument("--rest-byte", type=int, default=8)
    ap.add_argument("--start-wait", type=float, default=3.0)
    ap.add_argument("--client-args", default="")
    ap.add_argument("--end-wait", type=float, default=1.0)
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
        ["gdb", "-q", "-batch", "-x", args.gdbcmd,
         "--args", args.bin, "-1", args.cfg],
        stdin=srv.fileno(), stdout=log, stderr=log,
        close_fds=False, pass_fds=(srv.fileno(),), env=env,
        cwd=ROOT, start_new_session=True,
    )
    time.sleep(args.start_wait)
    print(f"gdb_alive_at_trigger={proc.poll() is None}")
    wire_args = [sys.executable, os.path.join(HERE, args.client),
                 "--port", str(args.port)]
    if args.prime_data is not None:
        wire_args += ["--prime-data", args.prime_data,
                      "--prime-arg0", str(args.prime_arg0),
                      "--prime-rest", str(args.prime_rest),
                      "--prime-rest-byte", str(args.prime_rest_byte)]
    wire_args += ["--data", args.data, "--arg0", str(args.arg0),
                  "--rest", str(args.rest), "--rest-byte", str(args.rest_byte)]
    if args.client_args:
        wire_args += args.client_args.split()
    r = subprocess.run(wire_args, capture_output=True, text=True, timeout=20)
    print(f"client_rc={r.returncode} stdout=[{r.stdout.strip()}] stderr=[{r.stderr.strip()}]")
    time.sleep(args.end_wait)
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        rc = proc.wait()
    log.flush()
    log.close()
    srv.close()
    print(f"gdb_rc={rc} log={args.log}")


if __name__ == "__main__":
    main()
