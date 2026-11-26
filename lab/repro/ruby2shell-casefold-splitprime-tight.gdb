# Analysis-only observer for the tight split-prime driver: print exact+1 and
# its offset from the primed chunk. No writes, no marker.
set pagination off
set confirm off
set print thread-events off
python
import gdb
class FoldProbe(gdb.Breakpoint):
    def __init__(self):
        super().__init__('regexec.c:4278', internal=True)
        self.n = 0
    def stop(self):
        big = int(gdb.parse_and_eval('splitprime_tight_g_big'))
        front = int(gdb.parse_and_eval('splitprime_tight_g_front'))
        t = int(gdb.parse_and_eval('(char *)t'))
        tend = int(gdb.parse_and_eval('(char *)tend'))
        if tend - t != 1 or self.n >= 32:
            return False
        b = gdb.selected_inferior().read_memory(t, 2).tobytes()
        self.n += 1
        print('FOLD_HIT n=%d big=%x front=%x t=%x delta_big=%d delta_front=%d t0=%02x t1=%02x' %
              (self.n, big, front, t, t - big, t - front, b[0], b[1]))
        return False
FoldProbe()
end
run
quit
