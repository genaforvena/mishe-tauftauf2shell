#!/usr/bin/env python3
"""Read record 2's header or first payload bytes from a pinned nfcapd capture.

With no second argument this finds the two-record alias datagram's record 2
header/element prefix and prints its first 8 payload bytes. With "hdr" it
locates record 2 by its distinct inPackets/inBytes pair and prints the
captured record header's exporterID and flags/nfversion bytes.
"""
import struct
import sys

PREFIX = bytes.fromhex("0b004800020000000000000301003400")


def main():
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    if len(sys.argv) > 2 and sys.argv[2] == "etype":
        marker = struct.pack("<QQ", 5, 500)  # flow inPackets/inBytes
        pos = data.rfind(marker)
        if pos < 0:
            print("REC2_FOUND=0")
            return 1
        # record 2 starts 40 B before inPackets: 12 B header + 4 B element
        # header + 24 B to inPackets inside the flow view.
        header = data[pos - 40:pos - 28]
        elem = data[pos - 28:pos - 24]
        print("REC2_FOUND=1 REC2_TYPE=" + elem[0:2].hex()
              + " REC2_LENGTH=" + elem[2:4].hex()
              + " REC2_FLAGS_NFVERSION=" + header[10:12].hex()
              + " REC2_SIZE=" + header[2:4].hex())
        return 0

    if len(sys.argv) > 2 and sys.argv[2] == "hdr":
        marker = struct.pack("<QQ", 5, 500)  # victim's inPackets/inBytes
        pos = data.rfind(marker)
        if pos < 0:
            print("REC2_FOUND=0")
            return 1
        header = data[pos - 24 - 16:pos - 24]
        print("REC2_FOUND=1 REC2_EXPORTER=" + header[8:10].hex()
              + " REC2_FLAGS_NFVERSION=" + header[10:12].hex()
              + " REC2_SIZE=" + header[2:4].hex())
        return 0
    pos = data.rfind(PREFIX)
    if pos < 0:
        print("REC2_FOUND=0")
        return 1
    start = pos + len(PREFIX)
    first = data[start:start + 8]
    print("REC2_FOUND=1 REC2_MSECFIRST=" + first.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
