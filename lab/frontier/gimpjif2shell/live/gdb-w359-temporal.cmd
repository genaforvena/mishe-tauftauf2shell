# W359: read-only temporal probe of the W358 predicted loader-array word.
# Software breakpoints + one hardware write watchpoint; no target writes.
set pagination off
set confirm off
set print thread-events off
python
import gdb, os, struct

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w359-temporal.log")
M = int(os.environ.get("W359_M", "0x5555556a0200"), 0)
DELTA = int(os.environ.get("W359_DELTA", "0x47210"), 0)
_log = open(LOG_PATH, "w", buffering=1)
state = {"idx": None, "strm": None, "target": None, "watch": None,
         "watch_hits": 0, "entry_snap": False}


def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")


def reg(name):
    return int(gdb.parse_and_eval("$" + name))


def words(addr, count):
    raw = gdb.selected_inferior().read_memory(addr, count * 8).tobytes()
    return struct.unpack("<%dQ" % count, raw)


def snapshot(tag):
    idx = state["idx"]
    target = state["target"]
    try:
        vals = words(target - 0x400, 0x800 // 8)
        hits = [(i - 0x80) * 8 for i, v in enumerate(vals) if v == M]
        center = words(target, 4)
        emit("W359 %s idx=%#x target=%#x off=%#x center=%s M=%#x "
             "M_HITS=%s" %
             (tag, idx, target, target - idx,
              ",".join("%#x" % v for v in center), M,
              ",".join("%#x" % x for x in hits[:32]) or "none"))
    except Exception as e:
        emit("W359 %s target=%#x READ_ERROR=%s" % (tag, target, e))


class WriteWatch(gdb.Breakpoint):
    def __init__(self, addr):
        super(WriteWatch, self).__init__(
            "*%#x" % addr, gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=True)
        self.addr = addr

    def stop(self):
        state["watch_hits"] += 1
        n = state["watch_hits"]
        try:
            before = words(self.addr, 1)[0]
        except Exception as e:
            before = str(e)
        pc = reg("pc")
        emit("W359 WRITE_WATCH n=%d addr=%#x pc=%#x value_before=%s" %
             (n, self.addr, pc, before))
        if n <= 4:
            try:
                for line in gdb.execute("x/4i $pc", to_string=True).splitlines():
                    emit("W359 WATCH_INS " + line.strip())
            except Exception as e:
                emit("W359 WATCH_INS ERROR %s" % e)
        if n >= 16:
            self.delete()
            state["watch"] = None
        return False


class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        strm = state["strm"]
        try:
            total = int(gdb.parse_and_eval("*(unsigned long*)(%d+40)" % strm))
            out = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            emit("W359 INFLATE_RETURN ret=%#x total_out=%#x next_out=%#x "
                 "avail_out=%#x watch_hits=%d" %
                 (reg("rax"), total, out, avail, state["watch_hits"]))
            snapshot("RETURN")
        except Exception as e:
            emit("W359 RETURN ERROR %s" % e)
        self.delete()
        return False


class EntryBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(EntryBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        if not state["entry_snap"]:
            state["entry_snap"] = True
            emit("W359 FIRST_ENTRY name=%s hash=%#x" %
                 (gdb.parse_and_eval("(char*)$rdi").string(), reg("rsi")))
            snapshot("FIRST_ENTRY")
        return False


class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = reg("rdi")
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483650:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            state["idx"] = idx
            state["strm"] = strm
            state["target"] = idx + DELTA
            emit("W359 PRE avail=%#x idx=%#x ret=%#x target=%#x M=%#x" %
                 (avail, idx, ret, state["target"], M))
            snapshot("PRE")
            try:
                state["watch"] = WriteWatch(state["target"])
                emit("W359 WRITE_WATCH ARMED addr=%#x" % state["target"])
            except Exception as e:
                emit("W359 WRITE_WATCH ARM_ERROR %s" % e)
            RetBP(ret)
            base = ld_base(gdb.selected_inferior().pid)
            if base:
                EntryBP(base + 0xa220)
                emit("W359 LD base=%#x" % base)
        except Exception as e:
            emit("W359 INFLATE ERROR %s" % e)
        return False


def ld_base(pid):
    with open("/proc/%d/maps" % pid) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 6 and parts[-1].endswith("ld-linux-x86-64.so.2") \
                    and parts[1] == "r--p":
                return int(parts[0].split("-")[0], 16)
    return None




def on_stop(ev):
    if isinstance(ev, gdb.SignalEvent) and ev.stop_signal in (
            "SIGSEGV", "SIGABRT", "SIGBUS"):
        emit("W359 SIGNAL %s pc=%#x watch_hits=%d" %
             (ev.stop_signal, reg("pc"), state["watch_hits"]))
        try:
            snapshot("SIGNAL")
        except Exception:
            pass


gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run

