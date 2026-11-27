# W320: no-shim GDB allocation-site trace with G_SLICE=always-malloc.
# GLib's default GSlice magazine may bypass glibc malloc for small objects;
# forcing always-malloc makes W317's malloc entry/return trace observable.
# Nothing is patched: no LD_PRELOAD shim, no plugin or heap byte change.
# The environment change is part of the claim and must be stated with it.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import re

sizes = []
allocs = {}

def sym(addr):
    try:
        s = gdb.execute("info symbol %#x" % addr, to_string=True).strip()
    except Exception:
        s = "no symbol"
    return s.splitlines()[0] if s else "no symbol"

class EntryBP(gdb.Breakpoint):
    def stop(self):
        try:
            sizes.append(int(gdb.parse_and_eval("$rdi")))
        except Exception:
            sizes.append(-1)
        return False

class RetBP(gdb.Breakpoint):
    def stop(self):
        try:
            ptr = int(gdb.parse_and_eval("$rax"))
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            size = sizes.pop() if sizes else -1
            allocs[ptr] = (size, ret)
        except Exception:
            pass
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
            print("W320 READ FAILED: %s" % e)
            return False
        print("=== W320 PRE-INFLATE indexes=%#x traced=%d ===" %
              (idx, len(allocs)))
        for off in (272, 304, 336, 368):
            p = idx + off
            hit = allocs.get(p)
            if hit:
                print("=== W320 ALLOC +%d size=%d caller=%#x sym=[%s] ===" %
                      (off, hit[0], hit[1], sym(hit[1])))
            else:
                print("=== W320 ALLOC +%d NOT TRACED ===" % off)
        for off in (264, 272, 280, 288, 296, 304, 328, 336, 344):
            try:
                v = int(gdb.parse_and_eval("*(unsigned long*)%d" % (idx + off)))
                print("=== W320 WORD +%d=%#018x ===" % (off, v))
            except Exception:
                pass
        return False

def on_objfile(ev):
    name = getattr(ev.new_objfile, "filename", None) or str(ev.new_objfile)
    if "libc.so.6" not in name or getattr(on_objfile, "armed", False):
        return
    on_objfile.armed = True
    for off in (270, 399, 568):
        RetBP("*malloc+%d" % off)
    EntryBP("malloc")

gdb.events.new_objfile.connect(on_objfile)
InspectBP("inflate")
end
run
