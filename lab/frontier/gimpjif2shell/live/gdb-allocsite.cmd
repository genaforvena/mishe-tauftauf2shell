# W317: no-shim GDB-only allocation-site trace for the live object at
# indexes+272 in the real GIMP 3.2.8 file-gif-load plug-in. Break at glibc
# malloc entry and at its three `ret` instructions, record (size, caller
# return address) per returned pointer, then report the recorded origin of
# the chunks at indexes+272/+304/+336/+368 when the wrapped inflate() call
# is reached. No preloaded shim, no modified heap or plugin bytes.
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
            print("W317 ALLOC READ FAILED: %s" % e)
            return False
        print("=== W317 ALLOC PRE-INFLATE indexes=%#x traced=%d ===" %
              (idx, len(allocs)))
        for off in (272, 304, 336, 368):
            p = idx + off
            hit = allocs.get(p)
            if hit:
                print("=== W317 ALLOC +%d size=%d caller=%#x sym=[%s] ===" %
                      (off, hit[0], hit[1], sym(hit[1])))
            else:
                print("=== W317 ALLOC +%d NOT TRACED (not malloc-returned) ===" % off)
        for off in (264, 272, 280, 304, 336, 344):
            try:
                v = int(gdb.parse_and_eval("*(unsigned long*)%d" % (idx + off)))
                print("=== W317 ALLOC WORD +%d=%#018x ===" % (off, v))
            except Exception:
                pass

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
