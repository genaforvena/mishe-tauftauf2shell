#!/usr/bin/env python3
"""Read record 2's first 8 bytes from a pinned nfcapd capture.

The two-record alias datagram makes record 1's truncated EXgenericFlow
store 8 packet-chosen bytes at record 2's payload offset 2. This helper
finds record 2's header/element prefix in the written capture and prints
its first 8 payload bytes, so the assertion does not depend on nfdump's
multi-threaded console interleaving.
"""
import sys

PREFIX = bytes.fromhex("0b004800020000000000000301003400")


def main():
    with open(sys.argv[1], "rb") as f:
        data = f.read()
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
