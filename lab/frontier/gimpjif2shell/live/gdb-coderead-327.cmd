# W327: no-shim post-inflate READ-watch sweep over *code-pointer* words.
# W325 watched only heap-pointer-looking words (+280/+336/+344/+376) and
# found zero reads before the plug-in faulted. Its read-only dump also shows
# words in executable mappings at +416/+424/+448/+752/+760/+784; those are
# the untested class of GTypePlugin/vtable/function-pointer slots whose
# consumption would be an indirect call or a qdata lookup. This script
# selects up to four such words from a pre-inflate read-only dump by checking
# /proc/<pid>/maps for executable mappings, then arms hardware READ
# watchpoints on those slots once real inflate() has returned.
# No register, heap byte, plugin byte or allocator state is modified.
# A hit is a candidate consumer, NOT a proven dereference or grade change.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W327_LOG", "/tmp/w327-coderead.log")
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

def word(addr):
    return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))

def proc_ranges():
    pid = gdb.selected_inferior().pid
    out = []
    with open("/proc/%d/maps" % pid) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 5 or "-" not in parts[0]:
                continue
            lo, hi = (int(x, 16) for x in parts[0].split("-"))
            out.append((lo, hi, parts[1], parts[-1]))
    return out

def find_map(v, ranges):
    for lo, hi, perms, path in ranges:
        if lo <= v < hi:
            return "%s+%#x perms=%s" % (path, v - lo, perms)
    return None

state = {"hits": 0, "idx": 0, "cands": [], "wps": []}

class ReadBP(gdb.Breakpoint):
    def __init__(self, addr, label):
        super(ReadBP, self).__init__("*((unsigned long*)%#x)" % addr,
                                     gdb.BP_WATCHPOINT, gdb.WP_READ)
        self.addr = addr
        self.label = label
        state["wps"].append(self)
        emit("W327 READ SET %s addr=%#x val=%#018x" %
             (label, addr, word(addr)))

    def stop(self):
        state["hits"] += 1
        pc = int(gdb.parse_and_eval("$pc"))
        emit("W327 READ HIT #%d %s addr=%#x pc=%#x val=%#018x" %
             (state["hits"], self.label, self.addr, pc, word(self.addr)))
        gdb.execute("bt 8")
        if state["hits"] >= 24:
            emit("W327 READ LIMIT reached; deleting all read watchpoints")
            for wp in list(state["wps"]):
                wp.delete()
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        idx = state["idx"]
        emit("W327 POST idx=%#x size264=%#x nq272=%#x" %
             (idx, word(idx + 264), word(idx + 272)))
        for addr, off, _old, _map in state["cands"]:
            try:
                ReadBP(addr, "+%d" % off)
            except Exception as e:
                emit("W327 READ SET FAILED +%d: %s" % (off, e))
        emit("W327 WATCHERS ARMED count=%d" % len(state["wps"]))
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
            emit("W327 PRE idx=%#x ret=%#x avail=%#x" % (idx, ret, avail))
            ranges = proc_ranges()
            exec_ranges = [r for r in ranges if "x" in r[2]]
            pc = int(gdb.parse_and_eval("$pc"))
            emit("W327 EXEC RANGES count=%d total=%d" %
                 (len(exec_ranges), len(ranges)))
            emit("W327 EXEC SELF pc=%#x map=%s" %
                 (pc, find_map(pc, exec_ranges)))
            cands = []
            for off in range(264, 1056, 8):
                try:
                    v = word(idx + off)
                except Exception as e:
                    emit("W327 WORD +%d FAILED %s" % (off, e))
                    continue
                emit("W327 WORD +%d=%#018x" % (off, v))
                desc = find_map(v, ranges)
                if v and v >= 0x7f0000000000 and off in (
                        416, 424, 448, 752, 760, 784):
                    emit("W327 MAPWORD +%d=%#x %s" % (off, v, desc))
                name = find_map(v, exec_ranges)
                if name and len(cands) < 4 and off >= 272:
                    cands.append((idx + off, off, v, name))
            state["cands"] = cands
            emit("W327 CANDIDATES %s" %
                 ", ".join("+%d=%#x(%s)" % (off, v, name)
                           for _a, off, v, name in cands))
            RetBP(ret)
        except Exception as e:
            emit("W327 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W327 SIGNAL %s pc=%#x" % (ev.stop_signal, pc))
    gdb.execute("info registers rip rax rdi rsi")
    try:
        emit("W327 SI_ADDR=%s" %
             gdb.parse_and_eval("$_siginfo->_siginfo._sifields._sigfault.si_addr"))
    except Exception as e:
        emit("W327 SI_ADDR FAILED %s" % e)
    gdb.execute("bt 10")

def on_exit(ev):
    emit("W327 EXITED hits=%d armed=%d" % (state["hits"], len(state["wps"])))

gdb.events.stop.connect(on_stop)
gdb.events.exited.connect(on_exit)
InflateBP("inflate")
end
run
