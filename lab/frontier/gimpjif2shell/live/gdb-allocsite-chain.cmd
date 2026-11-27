# W321: no-shim GDB allocation-family tracer with caller chains. Same
# validated static return offsets as gdb-allocsite-all.cmd, plus a short
# frame chain captured at each small allocation so the plugin-level caller
# of the chunk at indexes+272 can be named. No shim, no plugin or heap patch.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import collections

_log = open("/tmp/w321-alloc-chain.log", "w", buffering=1)

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
chains = {}
counts = collections.Counter()

def sym(addr):
    try:
        s = gdb.execute("info symbol %#x" % addr, to_string=True).strip()
    except Exception:
        return "no symbol"
    return s.splitlines()[0] if s else "no symbol"

def chain(depth=6):
    out = []
    f = gdb.newest_frame()
    for _ in range(depth):
        if not f:
            break
        try:
            out.append((f.name() or "?", int(f.pc())))
        except Exception:
            break
        f = f.older()
    return tuple(out)

class EntryBP(gdb.Breakpoint):
    def __init__(self, kind, spec):
        super(EntryBP, self).__init__(spec, internal=True)
        self.kind = kind

    def stop(self):
        try:
            if self.kind == "calloc":
                size = int(gdb.parse_and_eval("$rdi")) * int(gdb.parse_and_eval("$rsi"))
            elif self.kind in ("realloc", "aligned"):
                size = int(gdb.parse_and_eval("$rsi"))
            else:
                size = int(gdb.parse_and_eval("$rdi"))
            stacks[self.kind].append(size)
            counts["entry"] += 1
        except Exception as e:
            emit("W321 ENTRY ERROR %s %s" % (self.kind, e))
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, kind, off):
        super(RetBP, self).__init__("*%s+%#x" % (FAMILIES[kind][0], off), internal=True)
        self.kind = kind

    def stop(self):
        try:
            ptr = int(gdb.parse_and_eval("$rax"))
            caller = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            st = stacks[self.kind]
            size = st.pop() if st else -1
            allocs[ptr] = (size, caller, self.kind)
            counts["ret"] += 1
            if 0 < size <= 96:
                chains[ptr] = chain()
        except Exception as e:
            emit("W321 RET ERROR %s %s" % (self.kind, e))
        return False

class InspectBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            if not strm:
                return False
            if int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm)) != 2147483778:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
        except Exception as e:
            emit("W321 READ FAILED: %s" % e)
            return False
        emit("W321 PRE-INFLATE indexes=%#x entry=%d ret=%d traced=%d chains=%d" %
             (idx, counts["entry"], counts["ret"], len(allocs), len(chains)))
        for off in (0, 272, 280, 304, 336, 344):
            p = idx + off
            hit = allocs.get(p)
            if not hit:
                emit("W321 WORD +%d UNTRACED" % off)
                continue
            emit("W321 WORD +%d size=%d kind=%s caller=%#x sym=[%s]" %
                 (off, hit[0], hit[2], hit[1], sym(hit[1])))
            for name, pc in chains.get(p, ()):
                emit("W321 CHAIN +%d %s %#x [%s]" % (off, name, pc, sym(pc)))
        return False

def on_objfile(ev):
    name = getattr(ev.new_objfile, "filename", None) or str(ev.new_objfile)
    if "libc.so.6" not in name or getattr(on_objfile, "armed", False):
        return
    on_objfile.armed = True
    armed = 0
    for kind, (spec, rets) in FAMILIES.items():
        EntryBP(kind, spec)
        armed += 1
        for off in rets:
            RetBP(kind, off)
            armed += 1
    emit("W321 ARMED %d alloc-family breakpoints" % armed)

gdb.events.new_objfile.connect(on_objfile)
InspectBP("inflate")
end
run
