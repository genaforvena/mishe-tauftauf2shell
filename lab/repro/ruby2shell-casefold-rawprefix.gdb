# Analysis-only observer at the vulnerable OP_EXACTN_IC compare loop.
# Records fold length against remaining exact bytes; no writes, no marker.
set pagination off
set confirm off
python
import gdb
class ExactNFold(gdb.Breakpoint):
    def __init__(self):
        super().__init__('regexec.c:2830', internal=True)
        self.n = 0
    def stop(self):
        p = int(gdb.parse_and_eval('(char *)p'))
        endp = int(gdb.parse_and_eval('(char *)endp'))
        remain = endp - p
        ln = int(gdb.parse_and_eval('len')) + 1  # loop decrements before body
        self.n += 1
        if self.n <= 32:
            tag = 'OVERRUN' if ln > remain else 'FOLD_HIT'
            print('%s n=%d remain=%d len=%d' % (tag, self.n, remain, ln))
        return False
ExactNFold()
end
run
quit
