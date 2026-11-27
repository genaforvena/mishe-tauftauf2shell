# W337: no-shim live probe of the minimal geometry (33025x65026, alpha
# data_size=4, avail_out=0x80000002). Dump the 40-byte zlib overflow region
# around a 4-byte `indexes` chunk at the pinned inflate() call and return,
# map each OOB word against /proc/<pid>/maps to look for a code/data pointer
# candidate, and record the terminal fault frame. No register, heap word,
# plugin byte or allocator state is changed by this script.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w337-min.log")
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

def maps(pid):
    try:
        with open("/proc/%d/maps" % pid) as f:
            return [line.split() for line in f if " " in line]
    except Exception:
        return []

def classify(addr, ranges):
    for r in ranges:
        try:
            lo, hi = (int(x, 16) for x in r[0].split("-"))
        except Exception:
            continue
        if lo <= addr < hi:
            return "%s perms=%s" % (r[-1], r[1])
    return "None"

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
        emit("W337 RETURN pc=%#x sym=[%s]" %
             (int(gdb.parse_and_eval("$pc")), sym(int(gdb.parse_and_eval("$pc")))))
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
        except Exception as e:
            emit("W337 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W337 SIGNAL %s pc=%#x sym=[%s]" % (ev.stop_signal, pc, sym(pc)))
    gdb.execute("info registers rip rax rdi rsi")
    try:
        si = gdb.parse_and_eval("$_siginfo->_siginfo._sifields._sigfault.si_addr")
        emit("W337 SI_ADDR=%s" % si)
    except Exception as e:
        emit("W337 SI_ADDR FAILED %s" % e)
    gdb.execute("bt 10")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
