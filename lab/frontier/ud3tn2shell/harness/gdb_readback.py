#!/usr/bin/env python3
"""Drive one loopback bundle into a plain pinned daemon under gdb and read back
the bytes stored past the one-byte source-EID allocation. No off-loopback use.
"""
import argparse
import pathlib
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from wire_trigger import make_bundle  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--port", type=int, default=18224)
    ap.add_argument("--marker", type=int, default=0x5A)
    args = ap.parse_args()
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "gdb", "-q", "-batch", "-x", str(HERE / "readback.gdb"),
        "--args", args.binary,
        "-b", "6", "-e", "dtn://ud3tn.dtn/",
        "-c", f"mtcp:127.0.0.1,{args.port}",
        "-s", str(outdir / "readback.aap.sock"),
        "-S", str(outdir / "readback.aap2.sock"),
        "-L", "4",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    wire = make_bundle(marker=args.marker, count=64, eid_len=0)
    deadline = time.time() + 8
    sent = False
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", args.port), timeout=1) as s:
                s.sendall(wire)
                sent = True
            break
        except OSError:
            if proc.poll() is not None:
                break
            time.sleep(0.1)
    try:
        out, _ = proc.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    log = outdir / "gdb-readback.log"
    log.write_text(out)
    print(f"sent={sent} wire={len(wire)}B rc={proc.returncode} log={log}")
    for line in out.splitlines():
        if any(k in line for k in ("READBACK", "0x5a", "Breakpoint", "Error",
                                   "exited", "SIG", "heap")):
            print("   ", line)
    print("marker", hex(args.marker))


if __name__ == "__main__":
    main()
