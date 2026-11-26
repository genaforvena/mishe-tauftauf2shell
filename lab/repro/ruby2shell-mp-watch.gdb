# Same setup as ruby2shell-mp-header.gdb, but also install a temporary
# hardware READ watchpoint on the corrupted next-chunk size word as soon as
# the wire casemap buffer is allocated. A hit prints the consumer backtrace.
# Observed 2026-11-26: no read hit after a single mixed27 POST; consumer is
# UNKNOWN. Do not treat silence as a proven structural barrier.
set pagination off
set confirm off
set $np = 0
set logging file lab/build/evidence/mp-method-21/gdb-mp-watch.log
set logging overwrite on
set logging enabled on
python
class WatchSize(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__("*%d" % addr, gdb.BP_WATCHPOINT, gdb.WP_READ, False, True)
    def stop(self):
        gdb.write("=== READ of corrupted next-chunk size word ===\n")
        gdb.execute("bt 20")
        return True
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
  python WatchSize(int(gdb.parse_and_eval("$np")))
  continue
end

break string.c:7856 if $np != 0
commands
  silent
  printf "=== AFTER case_map ===\n"
  x/2gx $np
  disable $bpnum
  continue
end
run
