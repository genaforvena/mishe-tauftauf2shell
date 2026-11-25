import gdb


class FB(gdb.FinishBreakpoint):
    def __init__(self, n):
        gdb.FinishBreakpoint.__init__(self, gdb.newest_frame())
        self.n = n

    def stop(self):
        gdb.write("W10PY ret n=%d ptr=%s\n" % (self.n, self.return_value))
        return False


class MB(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__(self, "__libc_malloc")
        self.n = 0

    def stop(self):
        if self.n >= 30:
            return False
        self.n += 1
        gdb.write("W10PY enter n=%d size=%s top=0x%x\n" %
                  (self.n, gdb.parse_and_eval("$rdi"),
                   int(gdb.parse_and_eval("main_arena.top"))))
        FB(self.n)
        return False


def scan():
    inf = gdb.selected_inferior()
    buf = int(gdb.parse_and_eval("(unsigned long)data->buffer"))
    usable = int(gdb.parse_and_eval("(unsigned long)malloc_usable_size(data->buffer)"))
    base = buf + 2097272
    mem = bytes(inf.read_memory(base, 65536))
    gdb.write("W10PY buf=0x%x usable=%d boundary=0x%x nextsize=0x%lx top=0x%x\n" %
              (buf, usable, base, int.from_bytes(mem[0:8], "little"),
               int(gdb.parse_and_eval("main_arena.top"))))
    hits = []
    for off in range(0, 65536 - 7, 8):
        v = int.from_bytes(mem[off:off + 8], "little")
        if 0x400000 < v < 0x800000000000:
            try:
                s = gdb.execute("info symbol 0x%x" % v, to_string=True).strip()
            except Exception:
                s = "ERR"
            if s and not s.startswith("No symbol"):
                hits.append((off, v, s))
    gdb.write("W10PY codeptr_hits=%d\n" % len(hits))
    for off, v, s in hits[:20]:
        gdb.write("W10PY off=%d addr=0x%x sym=%s\n" % (off, v, s))
