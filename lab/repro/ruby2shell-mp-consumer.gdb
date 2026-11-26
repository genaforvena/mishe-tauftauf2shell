# Resolve the first post-overflow reader/free of the mixed27 successor chunk.
# Analysis only: the request path remains the unmodified stock Sinatra app.
#
# Launch in one shell:
#   RUBY2SHELL_STOCK_PORT=4566 gdb -q -batch -x lab/repro/ruby2shell-mp-consumer.gdb \
#     --args lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-stock-baseline.ru
# Send from another:
#   python3 lab/repro/ruby2shell-mp-method-21.py 4566 mixed27
#
# Observed on affected 3.4.12: the first read is Ruby's own copy-out at
# string.c:7866; the successor is then freed by mapping_buffer_free at
# string.c:7873. No external reader appears before that self-free.
set pagination off
set confirm off
set $np = 0
set logging file lab/build/evidence/mp-method-21/gdb-mp-consumer.log
set logging overwrite on
set logging enabled on

python
import gdb

armed = False
target = 0

class AfterCaseMap(gdb.Breakpoint):
    def stop(self):
        global armed, target
        candidate = int(gdb.parse_and_eval("$np"))
        if candidate == 0:
            return False
        armed = True
        target = candidate
        print("=== AFTER case_map target=%#x ===" % target)
        gdb.execute("x/2gx %#x" % target)
        WatchTarget(target)
        FreeTarget(target + 8)
        self.enabled = False
        return False

class WatchTarget(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__("*%#x" % addr, gdb.BP_WATCHPOINT,
                         gdb.WP_READ, False, True)
    def stop(self):
        frame = gdb.newest_frame()
        while frame is not None:
            if frame.name() == "rb_str_casemap":
                print("=== SELF copy-out read ignored ===")
                return False
            frame = frame.older()
        print("=== EXTERNAL READ target=%#x ===" % target)
        gdb.execute("bt 30")
        return True

class FreeTarget(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__("__libc_free", internal=True)
        self.addr = addr
    def stop(self):
        if not armed:
            return False
        rdi = int(gdb.parse_and_eval("$rdi"))
        if rdi != self.addr:
            return False
        print("=== FREE successor user=%#x ===" % rdi)
        gdb.execute("bt 30")
        return True

AfterCaseMap("string.c:7856")
end

break abort
commands
  printf "=== ABORT ===\n"
  bt 30
  quit
end

break string.c:7839 if current_buffer->capa == 48
commands
  silent
  set $np = (char *)current_buffer + 72
  printf "=== BEFORE buffer=%p next_size_at=%p ===\n", current_buffer, $np
  x/2gx $np
  continue
end

run
