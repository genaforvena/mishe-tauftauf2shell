# gdb watch for the pinned 3.4.11 repeat-ID write. Breakpoints are created
# once at startup, disabled, and enabled only when the oversized pattern
# reaches rb_reg_initialize. Only negative repeat IDs are logged. The driver's
# marker file separates first-request writes from second-request writes.
import gdb
import os

hits = [0]
keep = []
marked = [False]
marker = os.environ.get("RUBY2SHELL_ONIGMO_SECOND_MARKER")


def dump(expr):
    print(gdb.execute("x/8gx (char *)%s - 32" % expr, to_string=True))


class WriteBreak(gdb.Breakpoint):
    def __init__(self, address, label):
        super().__init__(address, internal=True)
        self.label = label
        self.enabled = False
        keep.append(self)

    def stop(self):
        mem = int(gdb.parse_and_eval("mem"))
        if mem >= 0:
            return False
        if marker and not marked[0] and os.path.exists(marker):
            marked[0] = True
            print("ONIG_SECOND_MARK at_hit=%d" % (hits[0] + 1))
        hits[0] += 1
        target = int(gdb.parse_and_eval("&repeat_stk[mem]"))
        value = int(gdb.parse_and_eval("repeat_stk[mem]"))
        base = int(gdb.parse_and_eval("alloca_base"))
        print("ONIG_%s hit=%d mem=%d target=0x%x slot=%d base=0x%x delta=%d"
              % (self.label, hits[0], mem, target, value, base, target - base))
        if hits[0] <= 6 or marked[0] and hits[0] <= 12:
            dump("&repeat_stk[mem]")
        return False


pre_bp = WriteBreak("*(&match_at + 2410)", "BEFORE")
post_bp = WriteBreak("*(&match_at + 2464)", "AFTER")


class CompileBreak(gdb.Breakpoint):
    def __init__(self):
        super().__init__("rb_reg_initialize", internal=True)
        keep.append(self)

    def stop(self):
        try:
            length = int(gdb.parse_and_eval("len"))
        except gdb.error:
            return False
        if length <= 300000:
            return False
        print("ONIG_ARM len=%d" % length)
        pre_bp.enabled = True
        post_bp.enabled = True
        return False


CompileBreak()
gdb.execute("run")
