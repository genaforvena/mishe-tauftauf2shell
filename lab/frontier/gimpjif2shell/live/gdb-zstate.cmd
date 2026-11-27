# W344: read-only layout measurement at the pinned inflate() call.
# Records strm, strm->state (zlib inflate_state) and indexes (next_out),
# the byte offset between them, and the inflate_state header fields, then
# lets the run continue unchanged. No register, heap word, plugin byte or
# allocator state is modified by this script.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w344-zstate.log")
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

def word(addr):
    return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))

def u32(addr):
    return int(gdb.parse_and_eval("*(unsigned int*)%d" % addr))

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

# zlib 1.3.x inflate_state header field offsets (x86-64)
FIELDS = [
    (0, 8, "strm"), (8, 4, "mode"), (12, 4, "last"), (16, 4, "wrap"),
    (20, 4, "havedict"), (24, 4, "flags"), (28, 4, "dmax"),
    (32, 8, "check"), (40, 8, "total"), (48, 8, "head"),
    (56, 4, "wbits"), (60, 4, "wsize"), (64, 4, "whave"), (68, 4, "wnext"),
    (72, 8, "window"), (80, 8, "hold"), (88, 4, "bits"),
    (92, 4, "length"), (96, 4, "offset"), (100, 4, "extra"),
    (104, 8, "lencode"), (112, 8, "distcode"), (120, 4, "lenbits"),
    (124, 4, "distbits"), (128, 4, "ncode"), (132, 4, "nlen"),
    (136, 4, "ndist"), (140, 4, "have"), (144, 8, "next"),
]
SAVED = {}

class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            SAVED["strm"] = strm
            avail = u32(strm + 32)
            if avail != 2147483650:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            emit("W344 PRE avail=%#x idx=%#x" % (avail, idx))
            statep = int(gdb.parse_and_eval("*(void**)(%d+56)" % strm))
            SAVED["statep"] = statep
            SAVED["idx"] = idx
            inf = gdb.selected_inferior()
            ranges = maps(inf.pid)
            emit("W344 STRM=%#x STATE=%#x IDX=%#x DELTA=%#x pid=%s" %
                 (strm, statep, idx, statep - idx, inf.pid))
            emit("W344 STATE sym=[%s] map=[%s]" %
                 (sym(statep), classify(statep, ranges)))
            emit("W344 IDX map=[%s]" % classify(idx, ranges))
            for off, size, name in FIELDS:
                if size == 8:
                    v = word(statep + off)
                else:
                    v = u32(statep + off)
                if name in ("strm", "head", "window", "lencode", "distcode", "next"):
                    note = classify(v & ~0xfff, ranges)
                else:
                    note = ""
                emit("W344 FIELD %-9s +%-3d=%#018x %s" % (name, off, v, note))
            # raw words around the first 16 bytes of indexes, where OOB starts
            for off in range(0, 96, 8):
                emit("W344 IDXW +%-3d=%#018x map=[%s]" %
                     (off, word(idx + off), classify(word(idx + off) & ~0xfff, ranges)))
        except Exception as e:
            emit("W344 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    pc = int(gdb.parse_and_eval("$pc"))
    emit("W344 SIGNAL %s pc=%#x sym=[%s]" % (ev.stop_signal, pc, sym(pc)))
    gdb.execute("info registers")
    try:
        st = SAVED["strm"]
        emit("W344 TOTAL_OUT=%#x NEXT_OUT=%#x AVAIL=%#x" %
             (word(st + 40), word(st + 24), u32(st + 32)))
    except Exception as e:
        emit("W344 TOTAL_OUT FAILED %s" % e)
    try:
        sp = SAVED["statep"]
        for off, size, name in FIELDS:
            if name not in ("wbits", "wsize", "whave", "wnext", "window",
                            "lencode", "distcode", "hold", "bits", "length"):
                continue
            v = word(sp + off) if size == 8 else u32(sp + off)
            emit("W344 POSTFIELD %-9s +%-3d=%#018x" % (name, off, v))
    except Exception as e:
        emit("W344 POSTFIELD FAILED %s" % e)
    try:
        si = gdb.parse_and_eval("$_siginfo->_siginfo._sigfault.si_addr")
        emit("W344 SI_ADDR=%s" % si)
    except Exception as e:
        emit("W344 SI_ADDR FAILED %s" % e)
    gdb.execute("bt 12")

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
