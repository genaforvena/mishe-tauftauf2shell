# W340: no-shim differential on the minimal-geometry JIF. Same pinned inflate
# breakpoint as W337, but after inflate returns, watch the chosen word at
# indexes+32 and the target address it contains for any read. A hit is a
# measured pointer use; no hit is a preserved negative, not proof of absence.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w340-watch.log")
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
    def __init__(self, tag, expr):
        super(WatchBP, self).__init__(expr, gdb.BP_WATCHPOINT, gdb.WP_READ,
                                      internal=True)
        self.tag = tag

    def stop(self):
        emit("W340 WATCH %s HIT pc=%#x sym=[%s]" %
             (self.tag, int(gdb.parse_and_eval("$pc")),
              sym(int(gdb.parse_and_eval("$pc")))))
        gdb.execute("bt 6")
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        idx = state["idx"]
        chosen = word(idx + 32)
        emit("W340 POST idx=%#x +24=%#018x +32=%#018x" %
             (idx, word(idx + 24), chosen))
        try:
            WatchBP("slot32", "*(unsigned long*)%d" % (idx + 32))
            emit("W340 WATCH slot32 armed at %#x" % (idx + 32))
        except Exception as e:
            emit("W340 WATCH slot32 ARM FAILED %s" % e)
        if chosen and chosen & 0xfff0000000000000 == 0:
            try:
                WatchBP("target", "*(unsigned char*)%d" % chosen)
                emit("W340 WATCH target armed at %#x" % chosen)
            except Exception as e:
                emit("W340 WATCH target ARM FAILED %s" % e)
        self.delete()
        return False

class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483650:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            inf = gdb.selected_inferior()
            state["idx"] = idx
            emit("W340 PRE avail=%#x idx=%#x pid=%s" % (avail, idx, inf.pid))
            RetBP(ret)
        except Exception as e:
            emit("W340 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W340 SIGNAL %s pc=%#x sym=[%s]" % (ev.stop_signal, pc, sym(pc)))
    gdb.execute("info registers rip rax rdi rsi")
    try:
        si = gdb.parse_and_eval("$_siginfo->_siginfo._sifields._sigfault.si_addr")
        emit("W340 SI_ADDR=%s" % si)
    except Exception as e:
        emit("W340 SI_ADDR FAILED %s" % e)
    gdb.execute("bt 10")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
