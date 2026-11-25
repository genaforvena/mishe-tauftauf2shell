import gdb

class FB(gdb.FinishBreakpoint):
    def __init__(self, n):
        gdb.FinishBreakpoint.__init__(self, gdb.newest_frame())
        self.n = n
    def stop(self):
        gdb.write("W7PY ret n=%d ptr=%s\n" % (self.n, self.return_value))
        return False

class MB(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__(self, "__libc_malloc")
        self.n = 0
    def stop(self):
        if self.n >= 24:
            return False
        self.n += 1
        gdb.write("W7PY enter n=%d size=%s top=%s\n" %
                  (self.n, gdb.parse_and_eval("$rdi"), gdb.parse_and_eval("main_arena.top")))
        FB(self.n)
        return False
