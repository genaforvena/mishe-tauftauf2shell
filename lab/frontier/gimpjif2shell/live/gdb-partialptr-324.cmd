# W324: no-shim probe of a *partial* overwrite of GData.qdatas.
# The 282-byte JIF preserves the GData chunk size (+264=0x21) and n_qdatas
# (+272=1) and rewrites only the low two bytes of qdatas (+280) to 0x4140,
# leaving its high six bytes intact. W313's zero-hit read watcher watched the
# *old* pointer target, which a full 0x4d overwrite destroys; this probe
# watches the recomputed target instead, after inflate has finished writing.
# No register, heap byte or plugin byte is changed by this script.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W324_LOG", "/tmp/w324-partialptr.log")
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

state = {"hits": 0, "expected": 0}

class WatchBP(gdb.Breakpoint):
    def __init__(self, addr, label):
        super(WatchBP, self).__init__("*((unsigned long*)%#x)" % addr,
                                      gdb.BP_WATCHPOINT, gdb.WP_ACCESS)
        self.addr = addr
        self.label = label
        emit("W324 WATCH SET %s addr=%#x" % (label, addr))

    def stop(self):
        state["hits"] += 1
        pc = int(gdb.parse_and_eval("$pc"))
        emit("W324 WATCH HIT #%d %s addr=%#x pc=%#x sym=[%s] val=%#018x" %
             (state["hits"], self.label, self.addr, pc, sym(pc), word(self.addr)))
        gdb.execute("bt 6")
        if state["hits"] >= 24:
            emit("W324 WATCH LIMIT reached; deleting both watchpoints")
            self.delete()
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        idx = state["idx"]
        exp = state["expected"]
        now = word(idx + 280)
        emit("W324 POST idx=%#x qdatas=%#x expected=%#x size264=%#x nq272=%#x" %
             (idx, now, exp, word(idx + 264), word(idx + 272)))
        emit("W324 OVERWRITE %s" % ("CONFIRMED" if now == exp else "MISMATCH"))
        WatchBP(exp, "qdatas-target-lo")
        WatchBP(exp + 8, "qdatas-target-hi")
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
            exp = (orig & ~0xffff) | 0x4140
            state.update(idx=idx, orig=orig, expected=exp, ret=ret)
            emit("W324 PRE idx=%#x orig=%#x expected=%#x ret=%#x" %
                 (idx, orig, exp, ret))
            for off in (256, 264, 272, 280, 288, 296, 304):
                emit("W324 WORD +%d=%#018x" % (off, word(idx + off)))
            RetBP(ret)
        except Exception as e:
            emit("W324 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W324 SIGNAL %s pc=%#x sym=[%s]" % (ev.stop_signal, pc, sym(pc)))
    gdb.execute("info registers rip rax rdi rsi")
    try:
        si = gdb.parse_and_eval("$_siginfo->_siginfo._sifields._sigfault.si_addr")
        emit("W324 SI_ADDR=%s expected=%#x" % (si, state["expected"]))
    except Exception as e:
        emit("W324 SI_ADDR FAILED %s" % e)
    gdb.execute("bt 10")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
