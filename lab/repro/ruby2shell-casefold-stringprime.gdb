# Analysis-only observer: print the byte at exact+1 when str_lower_case_match
# reads a one-byte reg->exact (tend - t == 1). Used with the string-prime
# driver on the plain 3.4.12 build. No writes, no marker.
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
        t = int(gdb.parse_and_eval('(char *)t'))
        tend = int(gdb.parse_and_eval('(char *)tend'))
        if tend - t != 1 or self.n >= 32:
            return False
        b = gdb.selected_inferior().read_memory(t, 2).tobytes()
        self.n += 1
        print('FOLD_HIT n=%d t0=%02x t1=%02x' % (self.n, b[0], b[1]))
        return False
FoldProbe()
end
run
quit
