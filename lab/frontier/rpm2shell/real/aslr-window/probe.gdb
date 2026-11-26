# Observe which liblua GC objects live inside the controlled copy window.
# GDB only observes: disable-randomization is off, no forced call, no write.
# A snapshot of the window is taken at every rpmcpioRead entry; the report
# uses the snapshot for the buf at the pinned post-copy site rpmfi.cc:2243.
set pagination off
set breakpoint pending on
set confirm off
break main
run
python
import struct
MASK = (1 << 64) - 1
snaps = {}
visits = []
seen = []
class EntryBP(gdb.Breakpoint):
    def stop(self):
        b = int(gdb.parse_and_eval("buf")) & MASK
        try:
            raw = gdb.selected_inferior().read_memory(b, 0x1000)
            snaps[b] = struct.unpack("<512Q", bytes(raw))
        except gdb.error as exc:
            gdb.write("SNAP_FAIL=%s %s\n" % (hex(b), exc))
        return False
class VisitBP(gdb.Breakpoint):
    def stop(self):
        visits.append(int(gdb.parse_and_eval("$r14")) & MASK)
        return False
EntryBP("rpmcpioRead")
VisitBP("*(&lua_resume + 0x206)")
def report():
    if not seen:
        return
    base = seen[0]
    vals = snaps.get(base)
    gdb.write("WINDOW_BUF=%s\n" % hex(base))
    gdb.write("VISIT_COUNT=%d\n" % len(visits))
    offsets = sorted({v - base for v in visits if base <= v < base + 0x1000})
    gdb.write("WINDOW_VISIT_OFFSETS=%d\n" % len(offsets))
    canonical = 0
    for off in offsets:
        v = vals[off // 8] if vals else None
        ok = v is not None and 0 < v < 0x0000800000000000
        if ok:
            canonical += 1
        gdb.write("CAND off=%#x pre=%s canonical=%d\n" %
                  (off, hex(v) if v is not None else "UNKNOWN", 1 if ok else 0))
    gdb.write("CANONICAL_PRECOPY_POINTERS=%d\n" % canonical)
    gdb.write("WINDOW_REPORT_DONE=1\n")
class CopyBP(gdb.Breakpoint):
    def stop(self):
        seen.append(int(gdb.parse_and_eval("buf")) & MASK)
        return False
CopyBP("rpmfi.cc:2243")
gdb.events.exited.connect(lambda ev: report())
end
continue
