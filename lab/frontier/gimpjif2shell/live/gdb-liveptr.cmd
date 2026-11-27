# W312: no-shim watchpoints on the two words of the live object directly
# following `indexes` in the real GIMP 3.2.8 file-gif-load plug-in. W252
# named that object (flags word 1 at indexes+272, heap pointer at +280)
# with a shim-assisted allocator trace; W307 watched only the chunk's size
# word at +264. This probe watches the live pointer field itself without
# changing any plugin byte, heap byte or allocator state.
#
# NOT asserted: chosen-address write, named-object *dereference*, control
# flow, marker or command. Grade stays rung 3 / rung 4 PARTIAL.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb

class WatchBP(gdb.Breakpoint):
    def __init__(self, addr, label):
        super(WatchBP, self).__init__("*((unsigned long*)%#x)" % addr,
                                      gdb.BP_WATCHPOINT, gdb.WP_WRITE)
        self.addr = addr
        self.label = label
        print("=== W312 WATCH SET %s at %#x ===" % (label, addr))
    def stop(self):
        try:
            val = int(gdb.parse_and_eval("*(unsigned long*)%d" % self.addr))
        except Exception as e:
            print("W312 WATCH READ FAILED: %s" % e)
            return False
        print("=== W312 WATCH HIT %s at %#x value=%#018x ===" % (self.label, self.addr, val))
        gdb.execute("bt 5")
        return False

class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            if not strm:
                return False
            # z_stream x86-64: next_in@0, avail_in@8, total_in@16,
            # next_out@24, avail_out@32, total_out@40.
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483778:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
        except Exception as e:
            print("W312 INFLATE READ FAILED: %s" % e)
            return False
        print("=== W312 PRE-INFLATE indexes=%#x avail_out=%u ===" % (idx, avail))
        gdb.execute("x/48gx %d" % (idx - 16))
        try:
            flags = int(gdb.parse_and_eval("*(unsigned long*)%d" % (idx + 272)))
            ptr = int(gdb.parse_and_eval("*(unsigned long*)%d" % (idx + 280)))
            print("=== W312 LIVE FIELDS flags=%#x ptr=%#018x ===" % (flags, ptr))
            WatchBP(idx + 272, "flags")
            WatchBP(idx + 280, "liveptr")
        except Exception as e:
            print("W312 WATCHPOINT SET FAILED: %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    inf = gdb.selected_inferior()
    print("=== W312 PLUGIN SIGNAL %s pid %s ===" % (ev.stop_signal, inf.pid))
    gdb.execute("info registers rip rsp rax")
    gdb.execute("bt 8")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
