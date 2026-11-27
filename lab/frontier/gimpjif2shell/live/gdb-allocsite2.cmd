# W319: no-shim GDB-only allocation-site trace for the live object at
# indexes+272 in the real GIMP 3.2.8 file-gif-load plug-in. At entry to
# malloc/calloc/realloc, arm a one-shot breakpoint at the caller's return
# address; record the returned pointer and caller address for filtered small
# allocations. At the wrapped inflate() call, match the pointer-bearing
# chunks after indexes to those allocations and resolve only their callers.
# No shim, no heap or plugin patch. Output is flushed to a file per line so
# a session kill cannot discard it.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import collections

LOG_PATH = "/tmp/w319-alloc-trace.log"
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

pending = collections.defaultdict(list)
allocs = {}
armed = set()
count = [0]

def sym(addr):
    try:
        s = gdb.execute("info symbol %#x" % addr, to_string=True).strip()
    except Exception:
        return "no symbol"
    return s.splitlines()[0] if s else "no symbol"

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)
        self.addr = addr

    def stop(self):
        try:
            ptr = int(gdb.parse_and_eval("$rax"))
            pc = int(gdb.parse_and_eval("$pc"))
            sizes = pending[self.addr]
            size = sizes.pop() if sizes else -1
            allocs[ptr] = (size, pc)
            count[0] += 1
            if size > 0 and size <= 80 and count[0] <= 400:
                emit("=== W319 ALLOC size=%d ptr=%#x caller=%#x ===" %
                     (size, ptr, pc))
        except Exception as e:
            emit("=== W319 RET ERROR %s ===" % e)
        self.delete()
        return False

class EntryBP(gdb.Breakpoint):
    def __init__(self, spec, kind):
        super(EntryBP, self).__init__(spec, internal=True)
        self.kind = kind

    def stop(self):
        try:
            if self.kind == "malloc":
                size = int(gdb.parse_and_eval("$rdi"))
            elif self.kind == "calloc":
                size = int(gdb.parse_and_eval("$rdi")) * int(gdb.parse_and_eval("$rsi"))
            else:
                size = int(gdb.parse_and_eval("$rsi"))
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            if size > 0 and size <= 80 and ret > 0x10000:
                pending[ret].append(size)
                if ret not in armed:
                    armed.add(ret)
                    RetBP(ret)
        except Exception as e:
            emit("=== W319 ENTRY ERROR %s %s ===" % (self.kind, e))
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
            emit("W319 READ FAILED: %s" % e)
            return False
        emit("=== W319 PRE-INFLATE indexes=%#x traced=%d ===" %
             (idx, len(allocs)))
        for off in (264, 272, 280, 296, 304, 328, 336, 344):
            try:
                v = int(gdb.parse_and_eval("*(unsigned long*)%d" % (idx + off)))
            except Exception:
                continue
            hit = allocs.get(idx + off)
            origin = "NOT TRACED"
            if hit:
                origin = "size=%d caller=%#x sym=[%s]" % (hit[0], hit[1], sym(hit[1]))
            emit("=== W319 WORD +%d=%#018x ALLOC: %s ===" % (off, v, origin))
        return False

def on_objfile(ev):
    name = getattr(ev.new_objfile, "filename", None) or str(ev.new_objfile)
    if "libc.so.6" not in name or getattr(on_objfile, "armed", False):
        return
    on_objfile.armed = True
    for kind in ("malloc", "calloc", "realloc"):
        try:
            EntryBP(kind, kind)
        except Exception as e:
            emit("W319 BP ERROR %s: %s" % (kind, e))

gdb.events.new_objfile.connect(on_objfile)
InspectBP("inflate")
end
run
