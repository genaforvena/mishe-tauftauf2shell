# W351: read-only observer for the second-stage pointer in the live loader.
# Same no-shim path and pinned inflate breakpoint as gdb-w349-chosen-deref.cmd;
# additionally logs the +0x354/+0x356 field reads when rbx is the file-chosen
# stage-2 value. No memory, register or plug-in byte is ever written.
set pagination off
set confirm off
set print thread-events off
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w351-stage2.log")
CHOSEN = 0x5555556c0240
P2 = int(os.environ.get("W351_P2", "0x%x" % CHOSEN), 0)
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

def word(addr):
    return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))

def byte(addr):
    return int(gdb.parse_and_eval("*(unsigned char*)%d" % addr))

def maps(pid):
    try:
        with open("/proc/%d/maps" % pid) as f:
            return [line.rstrip() for line in f]
    except Exception:
        return []

def classify(addr, ranges):
    for r in ranges:
        parts = r.split()
        if len(parts) < 2 or "-" not in parts[0]:
            continue
        try:
            lo, hi = (int(x, 16) for x in parts[0].split("-"))
        except Exception:
            continue
        if lo <= addr < hi:
            return parts[-1] if len(parts) > 5 else parts[1]
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
        dump("POST", state["idx"], maps(gdb.selected_inferior().pid))
        emit("W337 RETURN pc=%#x" % int(gdb.parse_and_eval("$pc")))
        self.delete()
        return False

class DerefBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(DerefBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        n = state["hits"]
        state["hits"] += 1
        rax = int(gdb.parse_and_eval("$rax"))
        chosen = (rax == CHOSEN)
        if n >= 8 and not chosen:
            return False
        inf = gdb.selected_inferior()
        ranges = maps(inf.pid)
        r14 = int(gdb.parse_and_eval("$r14"))
        loopidx = int(gdb.parse_and_eval("*(unsigned long*)($rsp+0xc0)"))
        emit("W349 %s n=%d pc=%#x rax=%#018x map=[%s] r14=%#x i=%d "
             "DELTA_FROM_IDX=%#x rbx=%#018x mem28=%#018x" %
             ("CHOSEN" if chosen else "DEREF", n,
              int(gdb.parse_and_eval("$pc")), rax,
              classify(rax & ~0xfff, ranges), r14, loopidx,
              r14 - state["idx"], int(gdb.parse_and_eval("$rbx")),
              word(rax + 0x28)))
        return False

class Stage2BP(gdb.Breakpoint):
    def __init__(self, addr, tag):
        super(Stage2BP, self).__init__("*%#x" % addr, internal=True)
        self.tag = tag

    def stop(self):
        rbx = int(gdb.parse_and_eval("$rbx"))
        if rbx != P2:
            return False
        ranges = maps(gdb.selected_inferior().pid)
        emit("W351 STAGE2 %s pc=%#x rbx=%#018x map=[%s] "
             "byte354=%#x byte356=%#x" %
             (self.tag, int(gdb.parse_and_eval("$pc")), rbx,
              classify(rbx & ~0xfff, ranges), byte(rbx + 0x354),
              byte(rbx + 0x356)))
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
            state["idx"] = idx
            emit("W337 PRE avail=%#x idx=%#x ret=%#x pid=%s" %
                 (avail, idx, ret, gdb.selected_inferior().pid))
            dump("PRE", idx, maps(gdb.selected_inferior().pid))
            emit("W351 P2=%#x" % P2)
            for line in gdb.execute("x/16i 0x7ffff7fd133e", to_string=True).splitlines():
                emit("W351 INS " + line.strip())
            RetBP(ret)
            DerefBP(0x7ffff7fd1327)
            Stage2BP(0x7ffff7fd1304, "skip354")
            Stage2BP(0x7ffff7fd133e, "test356")
            Stage2BP(0x7ffff7fd1356, "continue")
        except Exception as e:
            emit("W337 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    emit("W337 SIGNAL %s pc=%#x" %
         (ev.stop_signal, int(gdb.parse_and_eval("$pc"))))
    inf = gdb.selected_inferior()
    ranges = maps(inf.pid)
    rax = int(gdb.parse_and_eval("$rax"))
    rbx = int(gdb.parse_and_eval("$rbx"))
    def safe_word(addr):
        try:
            return word(addr)
        except Exception:
            return 0
    emit("W349 SIGNAL DEREF_HITS=%d rax=%#018x map=[%s] rbx=%#018x "
         "map=[%s] rbx356=%#018x" %
         (state["hits"], rax, classify(rax & ~0xfff, ranges), rbx,
          classify(rbx & ~0xfff, ranges), safe_word(rbx + 0x356)))
    try:
        arrbase = int(gdb.parse_and_eval("$r14"))
        emit("W345 LOOPIDX=%d ARRBASE=%#x DELTA_FROM_IDX=%#x" %
             (int(gdb.parse_and_eval("*(unsigned long*)($rsp+0xc0)")),
              arrbase, arrbase - state["idx"]))
        for i in range(0, 16):
            emit("W345 ARR[%d]=%#018x" % (i, word(arrbase + 8 * i)))
    except Exception as e:
        emit("W345 ARRAY ERROR %s" % e)
    for line in gdb.execute("x/10i $pc-24", to_string=True).splitlines():
        emit("W345 INS " + line.strip())
    gdb.execute("bt 10")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
