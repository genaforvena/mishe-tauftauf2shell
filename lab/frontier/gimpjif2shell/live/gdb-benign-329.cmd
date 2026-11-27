# W329: no-shim probe of a benign-prefix inflated image. The JIF writes
# zeros inside `indexes` and chosen bytes only past it, preserving +264=0x21
# and +272=1. Arms access watchpoints on the qdatas target recomputed at
# inflate entry. No register, heap byte or plugin byte is modified.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W329_LOG", "/tmp/w329-benign.log")
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

state = {"hits": 0, "idx": 0, "orig": 0, "target": 0, "ret": 0}

class WatchBP(gdb.Breakpoint):
    def __init__(self, addr, label):
        super(WatchBP, self).__init__("*((unsigned long*)%#x)" % addr,
                                      gdb.BP_WATCHPOINT, gdb.WP_ACCESS)
        self.addr = addr
        self.label = label
        emit("W329 WATCH SET %s addr=%#x" % (label, addr))

    def stop(self):
        state["hits"] += 1
        pc = int(gdb.parse_and_eval("$pc"))
        emit("W329 WATCH HIT #%d %s addr=%#x pc=%#x sym=[%s] val=%#018x" %
             (state["hits"], self.label, self.addr, pc, sym(pc), word(self.addr)))
        gdb.execute("bt 6")
        if state["hits"] >= 24:
            emit("W329 WATCH LIMIT reached; deleting watchpoint")
            self.delete()
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        target = state["target"]
        emit("W329 POST idx=%#x qdatas=%#x target=%#x size264=%#x nq272=%#x" %
             (state["idx"], word(state["idx"] + 280), target,
              word(state["idx"] + 264), word(state["idx"] + 272)))
        emit("W329 OVERWRITE %s" % ("CONFIRMED" if word(state["idx"] + 280) == target
                                    else "MISMATCH"))
        WatchBP(target, "qdatas-target-lo")
        WatchBP(target + 8, "qdatas-target-hi")
        self.delete()
        return False

class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483778:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            orig = word(idx + 280)
            changed = os.environ.get("W329_CHANGE", "0") == "1"
            target = ((orig & ~0xffff) | 0x4140) if changed else orig
            state.update(idx=idx, orig=orig, target=target, ret=ret)
            emit("W329 PRE idx=%#x orig=%#x target=%#x ret=%#x change=%s" %
                 (idx, orig, target, ret, changed))
            for off in (256, 264, 272, 280, 288, 296, 304, 312, 320):
                emit("W329 WORD +%d=%#018x" % (off, word(idx + off)))
            RetBP(ret)
        except Exception as e:
            emit("W329 INFLATE ERROR %s" % e)
        return False

class ProgressBP(gdb.Breakpoint):
    def __init__(self, spec, label):
        super(ProgressBP, self).__init__(spec)
        self.label = label

    def stop(self):
        emit("W329 REACHED %s pc=%#x" % (self.label, int(gdb.parse_and_eval("$pc"))))
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W329 SIGNAL %s pc=%#x sym=[%s] hits=%d" %
         (ev.stop_signal, pc, sym(pc), state["hits"]))
    gdb.execute("info registers rip rax rdi rsi")
    try:
        si = gdb.parse_and_eval("$_siginfo->_siginfo._sifields._sigfault.si_addr")
        emit("W329 SI_ADDR=%s target=%#x" % (si, state["target"]))
    except Exception as e:
        emit("W329 SI_ADDR FAILED %s" % e)
    gdb.execute("bt 10")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
ProgressBP("gimp_drawable_get_buffer", "gimp_drawable_get_buffer")
end
run
