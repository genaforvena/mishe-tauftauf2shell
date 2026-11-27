# W313: no-shim follow-up to W312. Observe the chosen-byte stores into the
# live object after `indexes` as before, then, once the real `inflate()`
# returns, install a READ watchpoint on the overwritten pointer word at
# indexes+280. Any read of that word is a candidate consumer; the SIGSEGV
# handler also prints si_addr to distinguish a chosen-address fault from
# collateral allocator-metadata corruption.
#
# NOT asserted: a dereference, chosen-address write, named object, control
# flow, marker or command. A zero read-hit log is a preserved negative.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
class WatchBP(gdb.Breakpoint):
    def __init__(self, addr, label):
        super(WatchBP, self).__init__("*((unsigned long*)%#x)" % addr,
                                      gdb.BP_WATCHPOINT, gdb.WP_WRITE)
        self.addr = addr
        self.label = label
        print("=== W313 WATCH SET %s at %#x ===" % (label, addr))
    def stop(self):
        try:
            val = int(gdb.parse_and_eval("*(unsigned long*)%d" % self.addr))
        except Exception:
            val = -1
        print("=== W313 WATCH HIT %s value=%#018x ===" % (self.label, val))
        gdb.execute("bt 4")
        return False


class ReadBP(gdb.Breakpoint):
    def __init__(self, addr, label):
        super(ReadBP, self).__init__("*((unsigned long*)%#x)" % addr,
                                     gdb.BP_WATCHPOINT, gdb.WP_READ)
        self.addr = addr
        self.label = label
        print("=== W313 READ SET %s at %#x ===" % (label, addr))
    def stop(self):
        try:
            val = int(gdb.parse_and_eval("*(unsigned long*)%d" % self.addr))
        except Exception:
            val = -1
        READ_HITS.append(val)
        print("=== W313 READ HIT %s value=%#018x count=%d ===" %
              (self.label, val, len(READ_HITS)))
        gdb.execute("bt 8")
        return False

class ReturnBP(gdb.Breakpoint):
    def stop(self):
        print("=== W313 INFLATE RETURNED idx=%#x ===" % IDX)
        try:
            ReadBP(IDX + 280, "liveptr")
            print("=== W313 READ WATCHER INSTALLED ===")
        except Exception as e:
            print("=== W313 READ WATCH INSTALL FAILED: %s ===" % e)
        return False

class InflateBP(gdb.Breakpoint):
    def stop(self):
        global IDX
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            if not strm:
                return False
            # z_stream x86-64: next_out@24, avail_out@32.
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483778:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
        except Exception as e:
            print("W313 INFLATE READ FAILED: %s" % e)
            return False
        IDX = idx
        print("=== W313 PRE-INFLATE indexes=%#x avail_out=%u ===" % (idx, avail))
        try:
            flags = int(gdb.parse_and_eval("*(unsigned long*)%d" % (idx + 272)))
            ptr = int(gdb.parse_and_eval("*(unsigned long*)%d" % (idx + 280)))
            print("=== W313 LIVE FIELDS flags=%#x ptr=%#018x ===" % (flags, ptr))
            WatchBP(idx + 272, "flags")
            WatchBP(idx + 280, "liveptr")
            caller = gdb.newest_frame().older()
            print("=== W313 RETURN PC %#x ===" % int(caller.pc()))
            ReturnBP("*%#x" % int(caller.pc()))
        except Exception as e:
            print("W313 WATCHPOINT SET FAILED: %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    inf = gdb.selected_inferior()
    print("=== W313 PLUGIN SIGNAL %s pid %s ===" % (ev.stop_signal, inf.pid))
    try:
        gdb.execute("info registers rip rsp rax")
    except Exception as e:
        print("W313 REGISTERS FAILED: %s" % e)
    try:
        print("=== W313 FAULT SI_ADDR %s ===" %
              gdb.parse_and_eval("$_siginfo._sifields._sigfault.si_addr"))
    except Exception as e:
        print("W313 SI_ADDR UNAVAILABLE: %s" % e)
    gdb.execute("bt 8")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
