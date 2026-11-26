# Analysis-only observer: print the byte at exact+1 when str_lower_case_match
# reads a one-byte reg->exact (tend - t == 1), and where that exact sits
# relative to the primed freed chunk. No writes, no marker.
set pagination off
set confirm off
python
import gdb
class FoldProbe(gdb.Breakpoint):
    def __init__(self):
        super().__init__('regexec.c:4278', internal=True)
        self.n = 0
    def stop(self):
        big = int(gdb.parse_and_eval('splitprime_g_big'))
        front = int(gdb.parse_and_eval('splitprime_g_front'))
        if self.n == 0:
            print('PRIME big=%x front=%x delta=%d' % (big, front, front - big))
        t = int(gdb.parse_and_eval('(char *)t'))
        tend = int(gdb.parse_and_eval('(char *)tend'))
        if tend - t != 1 or self.n >= 32:
            return False
        b = gdb.selected_inferior().read_memory(t, 2).tobytes()
        self.n += 1
        print('FOLD_HIT n=%d t=%x delta_big=%d t0=%02x t1=%02x' %
              (self.n, t, t - big, b[0], b[1]))
        return False
FoldProbe()
end
run
quit
