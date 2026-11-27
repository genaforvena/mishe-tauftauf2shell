# W325: no-shim post-inflate READ-watch sweep over the chosen-byte span.
# The 1024-byte JIF writes 760 chosen 0x4d bytes past the 264-byte
# `indexes` allocation; W302 showed this size does not take the layout-
# sensitive 8 KiB allocator fault. W313/W324 watched one word each and saw
# zero reads. This script chooses up to four heap-pointer-looking words in
# the OOB span from a pre-inflate read-only dump, then arms hardware READ
# watchpoints on those addresses once real inflate() has returned.
# No register, heap byte, plugin byte or allocator state is modified.
# A hit is a candidate consumer, NOT a proven dereference or grade change.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W325_LOG", "/tmp/w325-readsweep.log")
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

def word(addr):
    return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))

state = {"hits": 0, "idx": 0, "cands": [], "wps": []}

class ReadBP(gdb.Breakpoint):
    def __init__(self, addr, label):
        super(ReadBP, self).__init__("*((unsigned long*)%#x)" % addr,
                                     gdb.BP_WATCHPOINT, gdb.WP_READ)
        self.addr = addr
        self.label = label
        state["wps"].append(self)
        emit("W325 READ SET %s addr=%#x val=%#018x" %
             (label, addr, word(addr)))

    def stop(self):
        state["hits"] += 1
        pc = int(gdb.parse_and_eval("$pc"))
        emit("W325 READ HIT #%d %s addr=%#x pc=%#x val=%#018x" %
             (state["hits"], self.label, self.addr, pc, word(self.addr)))
        gdb.execute("bt 8")
        if state["hits"] >= 24:
            emit("W325 READ LIMIT reached; deleting all read watchpoints")
            for wp in list(state["wps"]):
                wp.delete()
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        idx = state["idx"]
        emit("W325 POST idx=%#x size264=%#x nq272=%#x qdatas280=%#x" %
             (idx, word(idx + 264), word(idx + 272), word(idx + 280)))
        for addr, off, _old in state["cands"]:
            try:
                ReadBP(addr, "+%d" % off)
            except Exception as e:
                emit("W325 READ SET FAILED +%d: %s" % (off, e))
        emit("W325 WATCHERS ARMED count=%d" % len(state["wps"]))
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
            state["idx"] = idx
            emit("W325 PRE idx=%#x ret=%#x avail=%#x" % (idx, ret, avail))
            cands = []
            for off in range(264, 1056, 8):
                try:
                    v = word(idx + off)
                except Exception as e:
                    emit("W325 WORD +%d FAILED %s" % (off, e))
                    continue
                emit("W325 WORD +%d=%#018x" % (off, v))
                if (len(cands) < 4 and off >= 272 and
                        0x500000000000 <= v < 0x600000000000):
                    cands.append((idx + off, off, v))
            state["cands"] = cands
            emit("W325 CANDIDATES %s" %
                 ", ".join("+%d=%#x" % (off, v) for _a, off, v in cands))
            RetBP(ret)
        except Exception as e:
            emit("W325 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W325 SIGNAL %s pc=%#x" % (ev.stop_signal, pc))
    gdb.execute("info registers rip rax rdi rsi")
    try:
        emit("W325 SI_ADDR=%s" %
             gdb.parse_and_eval("$_siginfo->_siginfo._sifields._sigfault.si_addr"))
    except Exception as e:
        emit("W325 SI_ADDR FAILED %s" % e)
    gdb.execute("bt 10")

def on_exit(ev):
    emit("W325 EXITED hits=%d armed=%d" % (state["hits"], len(state["wps"])))

gdb.events.stop.connect(on_stop)
gdb.events.exited.connect(on_exit)
InflateBP("inflate")
end
run
