# W321: no-shim GDB allocation-site trace across the glibc allocation family
# in the SHA-verified GIMP 3.2.8 AppImage. W317/W320 used three return offsets
# that are not `ret` instructions; all offsets here were verified with
# objdump against the AppImage libc:
#   malloc  0xa28d0-0xa2fc0: +0x91 +0x421 +0x522 +0x5ab
#   realloc 0xa3310-0xa39c0: +0x8b
#   calloc  0xa3b00-0xa3f70: +0x100 +0x26c
#   aligned_alloc 0xa3a00-0xa3a70: +0x45
#   pvalloc 0xa3aa0-0xa3b00: +0x50
# Static breakpoints only; no dynamic creation, shim, plugin or heap patch.
# The AppImage's g_slice_alloc jumps straight to g_malloc, so G_SLICE env
# cannot add a separate path in this build.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import collections

LOG_PATH = "/tmp/w321-alloc-all.log"
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

FAMILIES = {
    "malloc": ("malloc", (0x91, 0x421, 0x522, 0x5ab)),
    "realloc": ("realloc", (0x8b,)),
    "calloc": ("calloc", (0x100, 0x26c)),
    "aligned": ("aligned_alloc", (0x45,)),
    "pvalloc": ("pvalloc", (0x50,)),
}
stacks = {k: [] for k in FAMILIES}
allocs = {}
counts = collections.Counter()

def sym(addr):
    try:
        s = gdb.execute("info symbol %#x" % addr, to_string=True).strip()
    except Exception:
        return "no symbol"
    return s.splitlines()[0] if s else "no symbol"

class EntryBP(gdb.Breakpoint):
    def __init__(self, kind, spec):
        super(EntryBP, self).__init__(spec, internal=True)
        self.kind = kind

    def stop(self):
        try:
            if self.kind == "calloc":
                size = int(gdb.parse_and_eval("$rdi")) * int(gdb.parse_and_eval("$rsi"))
            elif self.kind == "realloc":
                size = int(gdb.parse_and_eval("$rsi"))
            elif self.kind == "aligned":
                size = int(gdb.parse_and_eval("$rsi"))
            elif self.kind == "pvalloc":
                size = int(gdb.parse_and_eval("$rdi"))
            else:
                size = int(gdb.parse_and_eval("$rdi"))
            stacks[self.kind].append(size)
            counts["entry"] += 1
        except Exception as e:
            emit("W321 ENTRY ERROR %s %s" % (self.kind, e))
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, kind, off):
        spec = "*%s+%#x" % (FAMILIES[kind][0], off)
        super(RetBP, self).__init__(spec, internal=True)
        self.kind = kind

    def stop(self):
        try:
            ptr = int(gdb.parse_and_eval("$rax"))
            caller = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            st = stacks[self.kind]
            size = st.pop() if st else -1
            allocs[ptr] = (size, caller, self.kind)
            counts["ret"] += 1
            if 0 < size <= 96 and counts["ret"] <= 120:
                emit("W321 ALLOC %s size=%d ptr=%#x caller=%#x sym=[%s]" %
                     (self.kind, size, ptr, caller, sym(caller)))
        except Exception as e:
            emit("W321 RET ERROR %s %s" % (self.kind, e))
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
                origin = "size=%d caller=%#x kind=%s sym=[%s]" % (
                    hit[0], hit[1], hit[2], sym(hit[1]))
            else:
                homes = [(a, v) for a, v in allocs.items()
                         if v[0] > 0 and a <= p < a + v[0]]
                if homes:
                    a, v = homes[-1]
                    origin = "INSIDE size=%d at %#x kind=%s sym=[%s]" % (
                        v[0], a, v[2], sym(v[1]))
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
    armed = 0
    for kind, (spec, rets) in FAMILIES.items():
        try:
            EntryBP(kind, spec)
            armed += 1
            for off in rets:
                RetBP(kind, off)
                armed += 1
        except Exception as e:
            emit("W321 BP ERROR %s: %s" % (kind, e))
    emit("W321 ARMED %d alloc-family breakpoints" % armed)

gdb.events.new_objfile.connect(on_objfile)
InspectBP("inflate")
end
run
