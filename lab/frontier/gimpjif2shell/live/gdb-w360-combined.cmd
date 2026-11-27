# W360: read-only temporal + loader-consumer observer for the hybrid JIF.
# Software breakpoints and one hardware WRITE watchpoint; no target writes.
set pagination off
set confirm off
set print thread-events off
python
import gdb, os, struct

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w360-combined.log")
M = int(os.environ.get("W360_M", "0x5555556a0200"), 0)
DELTA = int(os.environ.get("W360_DELTA", "0x47210"), 0)
IDX_NOM = int(os.environ.get("W360_IDX_NOM", "0x555555678ff0"), 0)
SPACING = int(os.environ.get("W360_SPACING", "0x600"), 0)
WATCH_LABELS = set(os.environ.get(
    "W360_WATCH_LABELS", "ARRAY,EARLY,MAP,ARRAYSTART").split(","))
KMAX = int(os.environ.get("W360_KMAX", "0x30"), 0)
_log = open(LOG_PATH, "w", buffering=1)
state = {"idx": None, "strm": None, "target": None, "watch": None,
         "watch_hits": 0, "armed": False, "entries": 0}


def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")


def reg(name):
    return int(gdb.parse_and_eval("$" + name))


def words(addr, count):
    raw = gdb.selected_inferior().read_memory(addr, count * 8).tobytes()
    return struct.unpack("<%dQ" % count, raw)


def u32(addr):
    return struct.unpack("<I", gdb.selected_inferior().read_memory(addr, 4).tobytes())[0]


def map_fields(addr):
    try:
        return ("l_addr=%#x l_real=%#x strtab=%#x symtab=%#x nb=%#x "
                "idxbits=%#x shift=%#x bitmask=%#x buckets=%#x chain=%#x "
                "type=%#x versyms=%#x used=%#x" %
                (words(addr, 1)[0], words(addr + 0x28, 1)[0],
                 words(addr + 0x68, 1)[0], words(addr + 0x70, 1)[0],
                 u32(addr + 0x32c), u32(addr + 0x330), u32(addr + 0x334),
                 words(addr + 0x338, 1)[0], words(addr + 0x340, 1)[0],
                 words(addr + 0x348, 1)[0], u32(addr + 0x354),
                 words(addr + 0x380, 1)[0], u32(addr + 0x414)))
    except Exception as e:
        return "FIELD_ERROR=%s" % e


def snapshot(tag):
    idx = state["idx"]
    target = state["target"]
    try:
        vals = words(target - 0x1000, 0x2000 // 8)
        hits = [(i - 0x200) * 8 for i, v in enumerate(vals) if v == M]
        center = words(target, 4)
        emit("W360 %s idx=%#x target=%#x off=%#x center=%s M=%#x "
             "M_HITS=%s" %
             (tag, idx, target, target - idx,
              ",".join("%#x" % v for v in center), M,
              ",".join("%#x" % x for x in hits[:32]) or "none"))
        emit("W360 %s MAP0 %s" % (tag, map_fields(M)))
        d = idx - IDX_NOM
        if d >= 0 and d % 16 == 0 and d // 16 <= KMAX:
            k = d // 16
            selected = M + SPACING * k
            emit("W360 %s PHASE k=%#x selector=%#x expected=%#x %s" %
                 (tag, k, words(M + 0x28, 1)[0], selected,
                  map_fields(selected)))
        else:
            emit("W360 %s PHASE idx_delta=%#x OUTSIDE" % (tag, d))
    except Exception as e:
        emit("W360 %s target=%#x READ_ERROR=%s" % (tag, target, e))


class WriteWatch(gdb.Breakpoint):
    def __init__(self, addr, label):
        super(WriteWatch, self).__init__(
            "*%#x" % addr, gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=True)
        self.addr = addr
        self.label = label
        self.count = 0

    def stop(self):
        state["watch_hits"] += 1
        self.count += 1
        n = self.count
        try:
            before = words(self.addr, 1)[0]
        except Exception as e:
            before = str(e)
        emit("W360 WRITE_WATCH label=%s n=%d addr=%#x pc=%#x value_before=%s" %
             (self.label, n, self.addr, reg("pc"), before))
        if n <= 4:
            try:
                for line in gdb.execute("x/4i $pc", to_string=True).splitlines():
                    emit("W360 WATCH_INS " + line.strip())
            except Exception as e:
                emit("W360 WATCH_INS ERROR %s" % e)
        if n >= 16:
            self.delete()
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
            emit("W360 INFLATE_RETURN ret=%#x total_out=%#x next_out=%#x "
                 "avail_out=%#x watch_hits=%d entries=%d" %
                 (reg("rax"), total, out, avail, state["watch_hits"],
                  state["entries"]))
            snapshot("RETURN")
        except Exception as e:
            emit("W360 RETURN ERROR %s" % e)
        self.delete()
        return False


class Watch(gdb.Breakpoint):
    def __init__(self, addr, label, limit=512):
        super(Watch, self).__init__("*%#x" % addr, internal=True)
        self.label = label
        self.limit = limit
        self.count = 0

    def stop(self):
        self.count += 1
        if self.count > self.limit:
            self.delete()
            return False
        try:
            if self.label == "ENTRY":
                state["entries"] += 1
                emit("W360 ENTRY n=%d name=%s hash=%#x flags=%#x scope=%#x" %
                     (self.count, gdb.parse_and_eval("(char*)$rdi").string(),
                      reg("rsi"), reg("rdx"), reg("r9")))
            elif self.label == "MATCH":
                emit("W360 MATCH n=%d rdi=%#x r9=%#x st_name=%#x map=%#x" %
                     (self.count, reg("rdi"), reg("r9"), u32(reg("r9")),
                      words(reg("rsp") + 40, 1)[0]))
            elif self.label == "LUSED":
                emit("W360 LUSED n=%d map=%#x l_used_before=%#x" %
                     (self.count, reg("r15"), u32(reg("r15") + 0x414)))
            elif self.label == "GOT":
                emit("W360 GOT n=%d rel_addr=%#x value=%#x" %
                     (self.count, reg("r13"), reg("rax")))
            elif self.label == "TABLE":
                emit("W360 TABLE n=%d rbx=%#x rdx=%#x rax=%#x hash=%#x %s" %
                     (self.count, reg("rbx"), reg("rdx"), reg("rax"),
                      reg("r12"), map_fields(reg("rbx"))))
            elif self.label == "ARRAY":
                base = state["idx"]
                r14 = reg("r14")
                emit("W360 ARRAY n=%d r14=%#x delta=%s rax=%#x mem0=%#x "
                     "mem8=%#x rsp40=%#x" %
                     (self.count, r14,
                      ("%#x" % (r14 - base)) if base else "UNKNOWN",
                      reg("rax"), words(r14, 1)[0], words(r14 + 8, 1)[0],
                      words(reg("rsp") + 40, 1)[0]))
        except Exception as e:
            emit("W360 %s ERROR %s" % (self.label, e))
        return False


class InflateBP(gdb.Breakpoint):
    def stop(self):
        if state["armed"]:
            return False
        try:
            strm = reg("rdi")
            avail = u32(strm + 32)
            if avail != 0x80000002:
                return False
            state["armed"] = True
            idx = words(strm + 24, 1)[0]
            ret = words(reg("rsp"), 1)[0]
            state["idx"] = idx
            state["strm"] = strm
            state["target"] = idx + DELTA
            emit("W360 PRE avail=%#x idx=%#x ret=%#x target=%#x M=%#x" %
                 (avail, idx, ret, state["target"], M))
            snapshot("PRE")
            try:
                if "ARRAY" in WATCH_LABELS:
                    state["watch"] = WriteWatch(state["target"], "ARRAY")
                    emit("W360 WRITE_WATCH ARMED label=ARRAY addr=%#x" %
                         state["target"])
                if "EARLY" in WATCH_LABELS:
                    WriteWatch(idx + 0x1000, "EARLY")
                    emit("W360 WRITE_WATCH ARMED label=EARLY addr=%#x" %
                         (idx + 0x1000))
                d = idx - IDX_NOM
                phase = d // 16 if d >= 0 and d % 16 == 0 else 0
                phase = min(max(phase, 0), KMAX)
                map_addr = idx + M - IDX_NOM
                if "MAP" in WATCH_LABELS:
                    WriteWatch(map_addr, "MAP")
                    emit("W360 WRITE_WATCH ARMED label=MAP addr=%#x phase=0 "
                         "selector_phase=%#x" % (map_addr, phase))
                if "ARRAYSTART" in WATCH_LABELS:
                    WriteWatch(idx + 0x47000, "ARRAYSTART")
                    emit("W360 WRITE_WATCH ARMED label=ARRAYSTART addr=%#x" %
                         (idx + 0x47000))
            except Exception as e:
                emit("W360 WRITE_WATCH ARM_ERROR %s" % e)
            RetBP(ret)
            base = ld_base(gdb.selected_inferior().pid)
            emit("W360 LD base=%s" % ("%#x" % base if base else "UNKNOWN"))
            if base:
                for off, label in ((0xa220, "ENTRY"), (0xa0a0, "MATCH"),
                                   (0xa2e1, "TABLE"), (0xb200, "LUSED"),
                                   (0x11257, "GOT"), (0xa327, "ARRAY")):
                    Watch(base + off, label)
        except Exception as e:
            emit("W360 INFLATE ERROR %s" % e)
        self.delete()
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
        emit("W360 SIGNAL %s pc=%#x watch_hits=%d entries=%d" %
             (ev.stop_signal, reg("pc"), state["watch_hits"], state["entries"]))
        snapshot("SIGNAL")
        try:
            emit("W360 BACKTRACE\n" + gdb.execute("bt 12", to_string=True))
        except Exception as e:
            emit("W360 BACKTRACE ERROR %s" % e)


gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
