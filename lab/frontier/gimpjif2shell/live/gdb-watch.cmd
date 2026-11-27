# W307: break on the real inflate() symbol, identify the wrapped call by
# zs.avail_out == 0x80000082, dump the live heap around zs.next_out (== the
# pinned `indexes` allocation), and set a write watchpoint on indexes+264 —
# the size word of the following glibc chunk. Every store past the 264-byte
# usable region is then reported with its real-library backtrace.
#
# GIMP invokes this under GIMP_PLUGIN_DEBUG_WRAP/WRAPPER. No plugin source,
# heap byte or allocator state is modified by the debugger. A watch hit is
# evidence of an OOB store, NOT of a named-object write, chosen-address write,
# marker or command. No grade change is asserted by this probe.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb

class WatchBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(WatchBP, self).__init__("*((unsigned long*)%#x)" % addr,
                                      gdb.BP_WATCHPOINT, gdb.WP_WRITE)
        self.addr = addr
        print("=== W307 WATCH SET at %#x ===" % addr)
    def stop(self):
        print("=== W307 OOB WATCH HIT at %#x ===" % self.addr)
        gdb.execute("bt 12")
        gdb.execute("x/16gx %d" % (self.addr - 16))
        return False

class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            if not strm:
                return False
            # z_stream on x86-64: next_in@0, avail_in@8, total_in@16,
            # next_out@24, avail_out@32, total_out@40 (uLong is 8 bytes).
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483778:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
        except Exception as e:
            print("W307 INFLATE READ FAILED: %s" % e)
            return False
        print("=== W307 PRE-INFLATE indexes=%#x avail_out=%u ===" % (idx, avail))
        gdb.execute("x/48gx %d" % (idx - 16))
        try:
            WatchBP(idx + 264)
        except Exception as e:
            print("W307 WATCHPOINT SET FAILED: %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    inf = gdb.selected_inferior()
    print("=== W307 PLUGIN SIGNAL %s pid %s ===" % (ev.stop_signal, inf.pid))
    gdb.execute("info registers rip rsp rax")
    gdb.execute("bt 12")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
