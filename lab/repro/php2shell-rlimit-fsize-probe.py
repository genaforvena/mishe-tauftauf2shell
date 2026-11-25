#!/usr/bin/env python3
"""Does RLIMIT_FSIZE kill a process mid-pwrite on this host?

Kernel check rw_verify_area() rejects a write whose (offset + count) exceeds
RLIMIT_FSIZE before copying any bytes, then raises SIGXFSZ.  If so there is no
partial-write window for CVE-2026-126714's splice: the session inode keeps the
carrier or is ftruncate-first, never prefix-of-new + tail-of-old.

Usage: python3 lab/repro/php2shell-rlimit-fsize-probe.py <outdir>
"""
import os
import resource
import signal
import sys


def main():
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "sess-probe")
    carrier = b"C" * 1584          # calibrated carrier length in the tfm lane
    replacement = b"R" * 1892      # FILE_START pwrite length in the tfm lane
    limit = 1019                   # calibrated K = len(carrnew)
    with open(path, "wb") as f:
        f.write(carrier)

    hits = []
    def on_xfsz(signum, frame):
        hits.append(signum)

    signal.signal(signal.SIGXFSZ, on_xfsz)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    fd = os.open(path, os.O_WRONLY)
    try:
        written = os.pwrite(fd, replacement, 0)
        error = ""
    except OSError as exc:
        written = -1
        error = f"{type(exc).__name__}: {exc.strerror} (errno {exc.errno})"
    finally:
        os.close(fd)

    with open(path, "rb") as f:
        after = f.read()
    result = (
        f"limit={limit} carrier={len(carrier)} replacement={len(replacement)}\n"
        f"pwrite returned: {written} {error}\n"
        f"SIGXFSZ deliveries caught: {hits}\n"
        f"file after: {len(after)} bytes, unchanged={after == carrier}\n"
    )
    print(result, end="")
    with open(os.path.join(outdir, "rlimit-fsize-probe.log"), "w") as f:
        f.write(result)


if __name__ == "__main__":
    main()
