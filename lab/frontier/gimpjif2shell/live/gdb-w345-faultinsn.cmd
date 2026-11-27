# W345: read-only diagnostic of the terminal W343 fault. Same pinned inflate
# breakpoint and PRE dump as gdb-min337.cmd; on the signal this script only
# reads mappings, registers, disassembly and stack words. No memory, register
# or plug-in byte is changed.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w345-faultinsn.log")
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

state = {"idx": 0}

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
            DerefBP()
        except Exception as e:
            emit("W337 INFLATE ERROR %s" % e)
        return False

class DerefBP(gdb.Breakpoint):
    hits = 0
    def __init__(self):
        super(DerefBP, self).__init__("*0x7ffff7fd132b", internal=True)

    def stop(self):
        rax = int(gdb.parse_and_eval("$rax"))
        if 0x555555570000 <= rax < 0x555555727000 and self.hits < 12:
            rbx = int(gdb.parse_and_eval("$rbx"))
            val = int(gdb.parse_and_eval("*(unsigned long*)(%d+40)" % rax))
            arr = int(gdb.parse_and_eval("$r14"))
            idx = int(gdb.parse_and_eval("*($rsp+0xc0)"))
            emit("W345 HEAPDEREF HIT n=%d rax=%#x rbx=%#x mem=%#x r14=%#x i=%d" %
                 (self.hits, rax, rbx, val, arr, idx))
            self.hits += 1
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W337 SIGNAL %s pc=%#x" % (ev.stop_signal, pc))
    gdb.execute("info registers")
    inf = gdb.selected_inferior()
    ranges = maps(inf.pid)
    emit("W345 PC MAP %s" % classify(pc, ranges))
    rax = int(gdb.parse_and_eval("$rax"))
    emit("W345 RAX MAP %s" % classify(rax, ranges))
    try:
        loopidx = int(gdb.parse_and_eval("*(unsigned long*)($rsp+0xc0)"))
        arrbase = int(gdb.parse_and_eval("$r14"))
        emit("W345 LOOPIDX=%d ARRBASE=%#x DELTA_FROM_IDX=%#x" %
             (loopidx, arrbase, arrbase - state["idx"]))
        for i in range(0, 16):
            emit("W345 ARR[%d]=%#018x" % (i, int(gdb.parse_and_eval(
                "*(unsigned long*)(%d)" % (arrbase + 8 * i)))))
    except Exception as e:
        emit("W345 ARRAY ERROR %s" % e)
    rdi = int(gdb.parse_and_eval("$rdi"))
    emit("W345 RDI MAP %s" % classify(rdi, ranges))
    rsi = int(gdb.parse_and_eval("$rsi"))
    emit("W345 RSI MAP %s" % classify(rsi, ranges))
    for line in gdb.execute("x/12i $pc-32", to_string=True).splitlines():
        emit("W345 INS " + line.strip())
    for line in gdb.execute("x/16gx $rsp", to_string=True).splitlines():
        emit("W345 STK " + line.strip())
    for line in maps(inf.pid):
        if "ld-linux" in line or "libz" in line or "[heap]" in line or "[stack]" in line:
            emit("W345 MAP " + line.strip())
    gdb.execute("bt 12")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
