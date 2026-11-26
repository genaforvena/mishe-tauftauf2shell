# Discover a live liblua GCObject address in the current deterministic layout.
# GDB only observes: no forced call, no injected write. The caller runs this
# against the SAME fixture path later used for the valid-target trace, because
# argv length shifts the GDB heap layout. The baseline A filler faults on a
# wild chosen pointer; visits recorded before that fault are live objects.
set pagination off
set breakpoint pending on
set confirm off
break main
run
python
import gdb
MASK = (1 << 64) - 1
state = {"copy_done": 0, "next_addr": 0}
class CopyBP(gdb.Breakpoint):
    def stop(self):
        state["copy_done"] = 1
        state["next_addr"] = (int(gdb.parse_and_eval("buf")) + 0x20) & MASK
        gdb.write("NEXT_ADDR=%s\n" % hex(state["next_addr"]))
        return False
class VisitBP(gdb.Breakpoint):
    def stop(self):
        if not state["copy_done"]:
            return False
        obj = int(gdb.parse_and_eval("$r14")) & MASK
        if 0 < obj < 0x0000800000000000:
            gdb.write("ALL_VISIT=%s%s\n" % (hex(obj),
                      "" if obj != state["next_addr"] else " OVERWRITTEN"))
            if obj != state["next_addr"]:
                gdb.write("LIVE_VISIT=%s\n" % hex(obj))
        return False
CopyBP("rpmfi.cc:2243")
VisitBP("*(&lua_resume + 0x206)")
end
continue
