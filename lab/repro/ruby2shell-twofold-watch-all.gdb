# W368: arm a hardware WRITE watchpoint on EVERY rb_str_casemap to_end.
# Run from the repository root (defaults n1=17, n2=19):
#   gdb -q -batch -x lab/repro/ruby2shell-twofold-watch-all.gdb \
#       lab/build/plain/ruby-3.4.12-plain/bin/ruby
# Environment overrides: R2S_N1, R2S_N2 (sharp-s counts in each operand).
# A trap is counted only while its own case_map call is active: a later fold
# can reuse the same heap address and write the stale watchpoint byte.
set pagination off
set confirm off
python
import os
n1 = os.environ.get("R2S_N1", "17")
n2 = os.environ.get("R2S_N2", "19")
gdb.execute("set args lab/repro/ruby2shell-twofold.rb %s %s" % (n1, n2))
print("ARGS n1=%s n2=%s" % (n1, n2))

traps = []
active_call = 0

class ToEndWatch(gdb.Breakpoint):
    def __init__(self, addr, callno):
        self.addr = addr
        self.callno = callno
        self.seen = False
        self.late_seen = False
        super().__init__("*((unsigned char *)%d)" % addr,
                         type=gdb.BP_WATCHPOINT, wp_class=gdb.WP_WRITE,
                         internal=True)
    def stop(self):
        frame = gdb.newest_frame()
        name = frame.name() or "?"
        line = frame.find_sal().line
        try:
            byte = int(gdb.parse_and_eval("*(unsigned char *)%d" % self.addr))
        except gdb.error:
            byte = -1
        if name == "case_map" and active_call == self.callno and not self.seen:
            self.seen = True
            traps.append((self.callno, self.addr, byte))
            print("TRAP call=%d addr=%#x byte=0x%02x frame=%s line=%s" %
                  (self.callno, self.addr, byte, name, line))
        elif not self.late_seen:
            self.late_seen = True
            print("LATE call=%d addr=%#x byte=0x%02x frame=%s active=%d line=%s" %
                  (self.callno, self.addr, byte, name, active_call, line))
        return False

class ReturnBreak(gdb.Breakpoint):
    def __init__(self):
        super().__init__("string.c:7850", internal=True)
    def stop(self):
        global active_call
        active_call = 0
        return False

class CallBreak(gdb.Breakpoint):
    def __init__(self):
        self.callno = 0
        super().__init__("string.c:7839", internal=True)
    def stop(self):
        global active_call
        self.callno += 1
        to = int(gdb.parse_and_eval("$rcx"))
        to_end = int(gdb.parse_and_eval("$r8"))
        print("CALL n=%d to=%#x to_end=%#x capa=%d" %
              (self.callno, to, to_end, to_end - to))
        active_call = self.callno
        ToEndWatch(to_end, self.callno)
        return False

CallBreak()
ReturnBreak()
end
run
python
print("SUMMARY n1=%s n2=%s traps=%d addrs=%s bytes=%s" %
      (n1, n2, len(traps),
       ",".join("%#x" % a for _, a, _ in traps),
       ",".join("0x%02x" % b for _, _, b in traps)))
end
quit
