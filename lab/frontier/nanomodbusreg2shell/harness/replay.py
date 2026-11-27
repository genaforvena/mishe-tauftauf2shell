#!/usr/bin/env python3
"""Run one client against the loopback malicious server and save logs."""

import os
import pathlib
import socket
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "harness" / "server.py"


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    client, name = sys.argv[1], sys.argv[2]
    port = str(free_port())
    env = os.environ.copy()
    env.update(
        NMBS_PORT=port,
        NMBS_COUNT=os.environ.get("NMBS_COUNT", "250"),
        NMBS_BYTE=os.environ.get("NMBS_BYTE", "0x41"),
        NMBS_MEM_HEX=os.environ.get("NMBS_MEM_HEX", ""),
    )
    srv = subprocess.Popen(
        [sys.executable, str(SERVER)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    ready = srv.stdout.readline().strip()
    if ready != "SERVER_READY":
        print("SERVER_START_FAILED", ready)
        srv.kill()
        return 2
    argv = [client, "127.0.0.1", port]
    if os.environ.get("NMBS_GDB"):
        argv = ["gdb", "-q", "-batch", "-x", os.environ["NMBS_GDB"], "--args"] + argv
    result = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=20,
    )
    server_out = srv.stdout.read()
    srv.wait(timeout=5)
    evidence = ROOT / "evidence"
    evidence.mkdir(exist_ok=True)
    (evidence / (name + ".client.out")).write_text(result.stdout)
    (evidence / (name + ".server.out")).write_text(server_out)
    print("CLIENT_RC", result.returncode)
    print("SERVER_ATTACK_SENT", "SERVER_ATTACK_SENT" in server_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
