# W341: no-shim live probe of the second upstream geometry (65535x32769,
# product 0x80007fff, alpha data_size=65534, ~32 KiB of chosen bytes past
# the 64 KiB indexes chunk). At the pinned inflate return, dump the OOB span
# once, classify its words, arm read watchpoints on a few live pointer words,
# and record any fault. No loader, shim or plug-in byte is changed.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os, re, struct

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w341-watch.log")
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

def word(addr):
    return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))

def sym(addr):
    try:
        out = gdb.execute("info symbol %#x" % addr, to_string=True).strip()
        return out.splitlines()[0] if out else "no symbol"
    except Exception:
        return "no symbol"

state = {"idx": 0}

class WatchBP(gdb.Breakpoint):
    def __init__(self, tag, addr):
        super(WatchBP, self).__init__("*(unsigned long*)%d" % addr,
                                      gdb.BP_WATCHPOINT, gdb.WP_READ,
                                      internal=True)
        self.tag = tag

    def stop(self):
        emit("W341 WATCH %s HIT pc=%#x sym=[%s]" %
             (self.tag, int(gdb.parse_and_eval("$pc")),
              sym(int(gdb.parse_and_eval("$pc")))))
        gdb.execute("bt 6")
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        idx = state["idx"]
        emit("W341 POST idx=%#x chunk_size=%#x first=%#x" %
             (idx, word(idx - 8), word(idx)))
        start = idx + 65520
        span = 32800
        try:
            buf = bytes(gdb.selected_inferior().read_memory(start, span))
            words = struct.unpack("<%dQ" % (span // 8), buf)
            chosen = 0x4d4d4d4d4d4d4d4d
            interesting = []
            for i, w in enumerate(words):
                if w != chosen and w not in (0, 0x21, 1):
                    interesting.append((start - idx + i * 8, w))
            emit("W341 OOB chosen_words=%d/%d nonchosen=%d" %
                 (sum(1 for w in words if w == chosen), len(words),
                  len(interesting)))
            for off, w in interesting[:60]:
                emit("W341 OOB idx+%d=%#018x" % (off, w))
        except Exception as e:
            emit("W341 OOB DUMP FAILED %s" % e)
        # Watch the first few non-chosen, mapped-looking words beyond the
        # object; a hit is a measured read, zero hits is a negative.
        armed = 0
        for off, w in interesting:
            if armed >= 6:
                break
            if not (0x555000000000 <= w < 0x7fff00000000):
                continue
            try:
                WatchBP("off+%d" % off, idx + off)
                emit("W341 WATCH armed off=%d word=%#x" % (off, w))
                armed += 1
            except Exception as e:
                emit("W341 WATCH ARM FAILED off=%d %s" % (off, e))
        self.delete()
        return False

class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147516415:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            inf = gdb.selected_inferior()
            state["idx"] = idx
            emit("W341 PRE avail=%#x idx=%#x pid=%s" % (avail, idx, inf.pid))
            RetBP(ret)
        except Exception as e:
            emit("W341 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W341 SIGNAL %s pc=%#x sym=[%s]" % (ev.stop_signal, pc, sym(pc)))
    gdb.execute("info registers rip rax rdi rsi")
    try:
        si = gdb.parse_and_eval("$_siginfo->_siginfo._sifields._sigfault.si_addr")
        emit("W341 SI_ADDR=%s" % si)
    except Exception as e:
        emit("W341 SI_ADDR FAILED %s" % e)
    gdb.execute("bt 10")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
