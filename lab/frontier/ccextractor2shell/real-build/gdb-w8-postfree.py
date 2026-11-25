import gdb

class FB(gdb.FinishBreakpoint):
    def __init__(self, n, tag):
        gdb.FinishBreakpoint.__init__(self, gdb.newest_frame())
        self.n = n
        self.tag = tag
    def stop(self):
        gdb.write("W8PY %s ret n=%d ptr=%s top=%s\n" %
                  (self.tag, self.n, self.return_value,
                   gdb.parse_and_eval("main_arena.top")))
        return False

class MB(gdb.Breakpoint):
    def __init__(self, tag, limit=80):
        gdb.Breakpoint.__init__(self, "__libc_malloc")
        self.tag = tag
        self.limit = limit
        self.n = 0
    def stop(self):
        if self.n >= self.limit:
            return False
        self.n += 1
        gdb.write("W8PY %s enter n=%d size=%s top=%s\n" %
                  (self.tag, self.n, gdb.parse_and_eval("$rdi"),
                   gdb.parse_and_eval("main_arena.top")))
        FB(self.n, self.tag)
        return False

before = MB("before")
after = None

def start_after():
    global after
    after = MB("after")

def heap_state(label):
    gdb.write("W8PY %s top=%s boundary=0x%s buf=%s\n" %
              (label, gdb.parse_and_eval("main_arena.top"),
               gdb.parse_and_eval("*(unsigned long*)($buf+2097272)"),
               gdb.parse_and_eval("$buf")))
