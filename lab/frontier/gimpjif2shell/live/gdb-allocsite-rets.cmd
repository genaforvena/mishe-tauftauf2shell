# W321: no-shim GDB allocation-site trace in the real GIMP 3.2.8 plug-in.
# W317/W320 armed malloc return breakpoints at offsets 270/399/568, but the
# SHA-verified AppImage glibc malloc has ret instructions only at the seven
# offsets below (objdump -d --start-address=0xa28d0 --stop-address=0xa3310),
# which explains traced=0 in both earlier attempts. This script uses those
# validated static return sites only: no dynamic breakpoint creation, no
# LD_PRELOAD shim, no plugin or heap-byte patch.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import collections

LOG_PATH = "/tmp/w321-alloc-rets.log"
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

RET_OFFS = (0x91, 0x421, 0x522, 0x5ab, 0x85b, 0x878, 0x9f8)
sizes = []
allocs = {}
counts = collections.Counter()

def sym(addr):
    try:
        s = gdb.execute("info symbol %#x" % addr, to_string=True).strip()
    except Exception:
        return "no symbol"
    return s.splitlines()[0] if s else "no symbol"

class EntryBP(gdb.Breakpoint):
    def stop(self):
        try:
            sizes.append(int(gdb.parse_and_eval("$rdi")))
            counts["entry"] += 1
        except Exception as e:
            emit("W321 ENTRY ERROR %s" % e)
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, off):
        super(RetBP, self).__init__("*malloc+%#x" % off, internal=True)
        self.off = off

    def stop(self):
        try:
            ptr = int(gdb.parse_and_eval("$rax"))
            caller = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            size = sizes.pop() if sizes else -1
            allocs[ptr] = (size, caller)
            counts["ret"] += 1
            if 0 < size <= 96 and counts["ret"] <= 300:
                emit("W321 ALLOC size=%d ptr=%#x caller=%#x sym=[%s]" %
                     (size, ptr, caller, sym(caller)))
        except Exception as e:
            emit("W321 RET ERROR %s %s" % (self.off, e))
        return False

class InspectBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            if not strm:
                return False
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483778:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
        except Exception as e:
            emit("W321 READ FAILED: %s" % e)
            return False
        emit("W321 PRE-INFLATE indexes=%#x entry=%d ret=%d traced=%d" %
             (idx, counts["entry"], counts["ret"], len(allocs)))
        for off in (0, 264, 272, 280, 288, 296, 304, 328, 336, 344, 368):
            p = idx + off
            hit = allocs.get(p)
            origin = "NOT TRACED"
            if hit:
                origin = "size=%d caller=%#x sym=[%s]" % (
                    hit[0], hit[1], sym(hit[1]))
            try:
                v = int(gdb.parse_and_eval("*(unsigned long*)%d" % p))
            except Exception:
                v = -1
            emit("W321 WORD +%d=%#018x ALLOC: %s" % (off, v, origin))
        return False

def on_objfile(ev):
    name = getattr(ev.new_objfile, "filename", None) or str(ev.new_objfile)
    if "libc.so.6" not in name or getattr(on_objfile, "armed", False):
        return
    on_objfile.armed = True
    EntryBP("malloc")
    for off in RET_OFFS:
        RetBP(off)
    emit("W321 ARMED entry + %d valid malloc ret sites" % len(RET_OFFS))

gdb.events.new_objfile.connect(on_objfile)
InspectBP("inflate")
end
run
