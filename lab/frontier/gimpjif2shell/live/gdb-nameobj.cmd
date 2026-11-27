# W317: no-shim inspection of the live object at indexes+272 in the real
# GIMP 3.2.8 file-gif-load plug-in. Stop at the wrapped inflate() call,
# dump glibc chunk metadata and the object's words, then resolve every
# pointer-like word to a symbol/mapping. No plugin bytes or heap bytes are
# modified; no shim is preloaded. A named object is a claim only if the
# pointer graph or an allocation site identifies it in this log.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import re

HEX = re.compile(r'^(0x)?[0-9a-fA-F]+$')

def word(addr):
    try:
        return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))
    except Exception:
        return None

def sym(value):
    try:
        s = gdb.execute("info symbol %#x" % value, to_string=True).strip()
    except Exception:
        s = "no symbol"
    return s.splitlines()[0] if s else "no symbol"

def describe(tag, addr, value):
    if value is None:
        print("=== W317 %s @%#x UNREADABLE ===" % (tag, addr))
        return
    print("=== W317 %s @%#x = %#018x sym=[%s] ===" % (tag, addr, value, sym(value)))

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
            print("W317 READ FAILED: %s" % e)
            return False
        print("=== W317 PRE-INFLATE indexes=%#x avail_out=%u ===" % (idx, avail))
        gdb.execute("x/28gx %d" % (idx + 256))
        # glibc: indexes usable=264, next chunk header at +264, user at +272.
        for off in (264, 272, 280, 288, 296, 304, 312, 320, 328, 336, 344, 352, 368):
            describe("word+%d" % off, idx + off, word(idx + off))
        first = word(idx + 272)
        ptr = word(idx + 280)
        if first is not None and ptr is not None:
            print("=== W317 FIELDS flags=%#x ptr=%#x delta=%d ===" %
                  (first, ptr, ptr - idx))
            print("=== W317 POINTED CHUNK ===")
            gdb.execute("x/8gx %d" % ptr)
            for off in (0, 8, 16, 24):
                describe("pointee+%d" % off, ptr + off, word(ptr + off))
        # Resolve any word in the corrupted span that looks like a code or
        # static-data pointer; a GTypeClass/GObject would surface here.
        for off in range(272, 400, 8):
            v = word(idx + off)
            if v and v > 0x10000:
                s = sym(v)
                if "No symbol" not in s and s != "no symbol":
                    print("=== W317 SYMBOL WORD +%d %#x [%s] ===" % (off, v, s))
        print("=== W317 MAPPINGS ===")
        print(gdb.execute("info proc mappings", to_string=True))
        gdb.execute("bt 6")
        return False

InspectBP("inflate")
end
run
