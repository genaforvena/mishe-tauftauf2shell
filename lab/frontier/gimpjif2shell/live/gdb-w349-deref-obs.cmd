# W349: read-only observation of the loader pointer-array dereference.
# Same pinned inflate breakpoint and PRE/POST dump as gdb-min337.cmd. At the
# pinned inflate entry, install a breakpoint on the already-identified loader
# dereference instruction. No memory, register or plug-in byte is changed:
# the script only prints state when the loader reaches that instruction.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w349-deref-obs.log")
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

def word(addr):
    return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))

def maps(pid):
    try:
        with open("/proc/%d/maps" % pid) as f:
            return [line.rstrip() for line in f]
    except Exception:
        return []

def classify(addr, ranges):
    for r in ranges:
        try:
            lo, hi = (int(x.split("-")[0], 16), int(x.split("-")[1].split()[0], 16))
        except Exception:
            continue
        if lo <= addr < hi:
            return r
    return "unmapped"

state = {"idx": 0, "hits": 0}

def dump(tag, idx, ranges):
    emit("W337 %s idx=%#x" % (tag, idx))
    for off in range(0, 80, 8):
        w = word(idx + off)
        emit("W337 %s +%-3d=%#018x map=[%s]" %
             (tag, off, w, classify(w & ~0xfff, ranges)))

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        idx = state["idx"]
        inf = gdb.selected_inferior()
        dump("POST", idx, maps(inf.pid))
        emit("W337 RETURN pc=%#x" % int(gdb.parse_and_eval("$pc")))
        self.delete()
        return False

class DerefObsBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(DerefObsBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        n = state["hits"]
        state["hits"] += 1
        if n >= 8:
            return False
        inf = gdb.selected_inferior()
        ranges = maps(inf.pid)
        rax = int(gdb.parse_and_eval("$rax"))
        r14 = int(gdb.parse_and_eval("$r14"))
        loopidx = int(gdb.parse_and_eval("*(unsigned long*)($rsp+0xc0)"))
        emit("W349 DEREF n=%d pc=%#x rax=%#018x map=[%s] r14=%#x i=%d "
             "DELTA_FROM_IDX=%#x" %
             (n, int(gdb.parse_and_eval("$pc")), rax,
              classify(rax & ~0xfff, ranges), r14, loopidx,
              r14 - state["idx"]))
        for i in range(0, 8):
            emit("W349 DEREF ARR[%d]=%#018x" %
                 (i, word(r14 + 8 * i)))
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
            emit("W337 PRE avail=%#x idx=%#x ret=%#x pid=%s" %
                 (avail, idx, ret, inf.pid))
            dump("PRE", idx, maps(inf.pid))
            RetBP(ret)
            DerefObsBP(0x7ffff7fd1327)
        except Exception as e:
            emit("W337 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    emit("W337 SIGNAL %s pc=%#x" % (ev.stop_signal, int(gdb.parse_and_eval("$pc"))))
    inf = gdb.selected_inferior()
    ranges = maps(inf.pid)
    emit("W349 SIGNAL DEREF_HITS=%d" % state["hits"])
    try:
        loopidx = int(gdb.parse_and_eval("*(unsigned long*)($rsp+0xc0)"))
        arrbase = int(gdb.parse_and_eval("$r14"))
        emit("W345 LOOPIDX=%d ARRBASE=%#x DELTA_FROM_IDX=%#x" %
             (loopidx, arrbase, arrbase - state["idx"]))
        for i in range(0, 16):
            emit("W345 ARR[%d]=%#018x" % (i, word(arrbase + 8 * i)))
    except Exception as e:
        emit("W345 ARRAY ERROR %s" % e)
    for line in gdb.execute("x/8i $pc-16", to_string=True).splitlines():
        emit("W345 INS " + line.strip())
    gdb.execute("bt 10")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
