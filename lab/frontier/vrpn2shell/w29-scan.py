import os
import gdb
import struct
"""gdb helper for probe-xlation-scan.sh: dump the .name slots before d_entry."""


def w29_scan():
    if getattr(gdb, "_w29_done", False):
        return
    gdb._w29_done = True
    base = int(gdb.parse_and_eval("&d_entry[0]"))
    inf = gdb.selected_inferior()
    start = base - 32016
    buf = bytes(inf.read_memory(start, 32016))
    print("SCAN base=%#x start=%#x useEntry=%d this=%#x" %
          (base, start, int(gdb.parse_and_eval("useEntry")),
           int(gdb.parse_and_eval("this"))))
    for k in range(-1999, 0):
        v = struct.unpack_from("<Q", buf, 32016 + 16 * k)[0]
        if v:
            print("SLOT k=%d addr=%#x value=%#x" % (k, base + 16 * k, v))
            if 0x500000000000 < v < 0x600000000000 and v & 7 == 0:
                gdb.execute("x/16gx %#x" % (v - 32))
                for off in range(8, 65537, 8):
                    w = struct.unpack_from("<Q", bytes(inf.read_memory(v - off, 8)), 0)[0]
                    if w:
                        print("PREV v-%#x = %#x (addr %#x)" % (off, w, v - off))
                        break
    path = os.environ.get("W29_HEAP_DUMP")
    if path:
        lo, hi = base - 0x20000, base + 0x8010
        with open(path, "wb") as f:
            f.write(bytes(inf.read_memory(lo, hi - lo)))
        print("DUMP lo=%#x hi=%#x" % (lo, hi))
    gdb.execute("quit")
