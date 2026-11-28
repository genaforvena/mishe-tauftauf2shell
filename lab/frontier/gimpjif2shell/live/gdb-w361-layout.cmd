# W361: read-only layout + loader observer for the larger wrapped geometry.
# Software breakpoints only (no hardware watchpoints): the W360 combined
# observer with hardware watchpoints broke its own W353 positive control.
# No target memory or register is written by this script.
set pagination off
set confirm off
set print thread-events off
python
import gdb, os, struct

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w361-layout.log")
AVAIL = int(os.environ.get("W361_AVAIL", "0x8000000c"), 0)
_log = open(LOG_PATH, "w", buffering=1)
_idx = [None]
_state = {"ret": None, "strm": None, "entries": 0}


def emit(msg):
    print(str(msg))
    _log.write(str(msg) + "\n")


def reg(name):
    return int(gdb.parse_and_eval("$" + name))


def maps(pid):
    with open("/proc/%d/maps" % pid) as f:
        return [line.rstrip() for line in f]


def ld_base(pid):
    for line in maps(pid):
        parts = line.split()
        if len(parts) >= 6 and parts[-1].endswith("ld-linux-x86-64.so.2") \
                and parts[1] == "r--p":
            return int(parts[0].split("-")[0], 16)
    return None


class Watch(gdb.Breakpoint):
    def __init__(self, addr, label, limit=24):
        super(Watch, self).__init__("*%#x" % addr, internal=True)
        self.label = label
        self.limit = limit
        self.count = 0

    def stop(self):
        self.count += 1
        if self.count > self.limit:
            self.delete()
            return False
        if self.label == "ENTRY":
            _state["entries"] += 1
            emit("W361 ENTRY n=%d name=%s hash=%#x scope=%#x" %
                 (self.count, gdb.parse_and_eval("(char*)$rdi").string(),
                  reg("rsi"), reg("r9")))
        elif self.label == "MATCH":
            emit("W361 MATCH n=%d rdi=%#x r9=%#x st_name=%#x map=%#x" %
                 (self.count, reg("rdi"), reg("r9"),
                  int(gdb.parse_and_eval("*(unsigned int*)($r9)")),
                  int(gdb.parse_and_eval("*(unsigned long*)($rsp+40)"))))
        elif self.label == "LUSED":
            emit("W361 LUSED n=%d map=%#x l_used_before=%#x" %
                 (self.count, reg("r15"),
                  int(gdb.parse_and_eval("*(unsigned int*)($r15+0x414)"))))
        elif self.label == "GOT":
            emit("W361 GOT n=%d rel_addr=%#x value=%#x" %
                 (self.count, reg("r13"), reg("rax")))
        elif self.label == "TABLE":
            emit("W361 TABLE n=%d rbx=%#x rdx=%#x rax=%#x hash=%#x" %
                 (self.count, reg("rbx"), reg("rdx"), reg("rax"), reg("r12")))
        elif self.label == "ARRAY":
            base = _idx[0]
            r14 = reg("r14")
            emit("W361 ARRAY n=%d r14=%#x delta=%s rax=%#x mem0=%#x mem8=%#x "
                 "rsp40=%#x" %
                 (self.count, r14,
                  ("%#x" % (r14 - base)) if base else "UNKNOWN",
                  reg("rax"),
                  int(gdb.parse_and_eval("*(unsigned long*)(%d)" % r14)),
                  int(gdb.parse_and_eval("*(unsigned long*)(%d+8)" % r14)),
                  int(gdb.parse_and_eval("*(unsigned long*)($rsp+40)"))))
        return False


watches = []


class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        strm = _state["strm"]
        try:
            total = int(gdb.parse_and_eval("*(unsigned long*)(%d+40)" % strm))
            out = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            emit("W361 INFLATE_RETURN ret=%#x total_out=%#x next_out=%#x "
                 "avail_out=%#x entries=%d" %
                 (reg("rax"), total, out, avail, _state["entries"]))
        except Exception as e:
            emit("W361 RETURN ERROR %s" % e)
        self.delete()
        return False


class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = reg("rdi")
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != AVAIL:
                return False
            _idx[0] = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            _state["strm"] = strm
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            emit("W361 PRE avail=%#x idx=%#x ret=%#x expected=%#x" %
                 (avail, _idx[0], ret, AVAIL))
            base = ld_base(gdb.selected_inferior().pid)
            emit("W361 LD base=%s" % ("%#x" % base if base else "UNKNOWN"))
            if base:
                for off, label in ((0xa220, "ENTRY"), (0xa0a0, "MATCH"),
                                   (0xa2e1, "TABLE"), (0xa327, "ARRAY"),
                                   (0xb200, "LUSED"), (0x11257, "GOT")):
                    watches.append(Watch(base + off, label))
                RetBP(ret)
        except Exception as e:
            emit("W361 INFLATE ERROR %s" % e)
        return False


def on_stop(ev):
    if isinstance(ev, gdb.SignalEvent) and ev.stop_signal in (
            "SIGSEGV", "SIGABRT", "SIGBUS"):
        emit("W361 SIGNAL %s pc=%#x rax=%#x rbx=%#x r14=%#x" %
             (ev.stop_signal, reg("pc"), reg("rax"), reg("rbx"), reg("r14")))


gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
