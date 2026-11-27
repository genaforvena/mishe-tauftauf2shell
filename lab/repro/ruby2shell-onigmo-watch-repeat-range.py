# W306: census the out-of-bounds `reg->repeat_range[mem]` metadata read for a
# wire-visible wrapped repeat ID (W305's named next experiment). At the armed
# BEFORE site (the `repeat_stk[mem] = GET_STACK_INDEX(stk)` write) dump the
# computed RepeatRange address, both ints, its struct size, the /proc maps line
# owning the address (or UNMAPPED), then arm a READ watchpoint with backtraces.
# Native `mem` conditions are installed by gdb `commands` blocks: Python stop()
# overrides bypass gdb conditions (measured in W302). `reg` is cached at
# match_at entry because it may optimize out at the BEFORE site.
import gdb
import os

state = {
    "last": "none",
    "mem": None,
    "range_addr": None,
    "reg": None,
    "reads": 0,
    "seen_pre": set(),
    "armed": False,
}
MAX_READS = int(os.environ.get("RUBY2SHELL_ONIGMO_MAX_READS", "5"))
MEM_COND = os.environ.get("RUBY2SHELL_ONIGMO_MEM_COND", "mem < 0 && mem > -129")


def note(text):
    print("ONIG_DEEP " + text, flush=True)


def kind(value):
    u = value & 0xFFFFFFFFFFFFFFFF
    if 0x7FFC00000000 <= u < 0x800000000000:
        return "stack"
    if 0x7F0000000000 <= u < 0x7FFC00000000:
        return "mmap"
    if 0x550000000000 <= u < 0x560000000000:
        return "pie"
    if value == 0:
        return "zero"
    if -1000000 < value < 1000000:
        return "small"
    return "other"


def mapping(addr):
    try:
        pid = gdb.selected_inferior().pid
        with open("/proc/%d/maps" % pid) as fh:
            for line in fh:
                lo, hi = (int(x, 16) for x in line.split()[0].split("-"))
                if lo <= addr < hi:
                    return line.strip()
        return "UNMAPPED"
    except Exception as exc:
        return "UNAVAILABLE %r" % (exc,)


class ReadBreak(gdb.Breakpoint):
    def __init__(self, address):
        super().__init__("*(long*)0x%x" % address, type=gdb.BP_WATCHPOINT,
                         wp_class=gdb.WP_READ, internal=True)
        self.address = address

    def stop(self):
        if state["reads"] >= MAX_READS:
            self.delete()
            return False
        state["reads"] += 1
        try:
            qword = int(gdb.parse_and_eval("*(long*)0x%x" % self.address))
            lo = int(gdb.parse_and_eval("*(int*)0x%x" % self.address))
            hi = int(gdb.parse_and_eval("*(int*)0x%x" % (self.address + 4)))
            note("READ %d addr=0x%x qword=0x%x lower=%d upper=%d mem=%d"
                 % (state["reads"], self.address, qword & 0xFFFFFFFFFFFFFFFF,
                    lo, hi, state["mem"]))
        except Exception as exc:
            note("READ_FAIL %d addr=0x%x %r" % (state["reads"], self.address, exc))
        note("READ_BT " + gdb.execute("bt 4", to_string=True).replace("\n", " | "))
        note("READ_MAP " + mapping(self.address))
        return False


def reg_value():
    try:
        return int(gdb.parse_and_eval("(long)reg"))
    except Exception:
        return state["reg"]


def onig_hit(label):
    try:
        mem = int(gdb.parse_and_eval("mem"))
    except Exception as exc:
        note("NO_MEM %s %r" % (label, exc))
        return
    state["mem"] = mem
    reg = reg_value()
    target = int(gdb.parse_and_eval("(long)&repeat_stk[mem]"))
    base = int(gdb.parse_and_eval("(long)alloca_base"))
    try:
        rr_addr = int(gdb.parse_and_eval("(long)&reg->repeat_range[mem]"))
    except Exception:
        try:
            off = int(gdb.parse_and_eval("(long)&((regex_t *)0)->repeat_range"))
            rr_addr = reg + off + mem * 8
        except Exception as exc:
            note("RR_ADDR_FAIL %s %r" % (label, exc))
            return
    state["range_addr"] = rr_addr
    try:
        size = int(gdb.parse_and_eval("sizeof(OnigRepeatRange)"))
    except Exception:
        size = 8
    try:
        lower = int(gdb.parse_and_eval("(int)reg->repeat_range[mem].lower"))
        upper = int(gdb.parse_and_eval("(int)reg->repeat_range[mem].upper"))
        vals = "lower=%d upper=%d" % (lower, upper)
    except Exception as exc:
        vals = "vals_UNAVAILABLE %r" % (exc,)
    state["last"] = ("mem=%d reg=0x%x(%s) rr=0x%x(%s) delta=%d size=%d %s "
                     "write_target=0x%x base=0x%x" %
                     (mem, reg & 0xFFFFFFFFFFFFFFFF, kind(reg),
                      rr_addr & 0xFFFFFFFFFFFFFFFF, kind(rr_addr),
                      rr_addr - reg, size, vals, target, base))
    note("%s %s" % (label, state["last"]))
    if label == "BEFORE" and rr_addr not in state["seen_pre"]:
        state["seen_pre"].add(rr_addr)
        note("PRE k=%d %s" % (-mem, state["last"]))
        note("RR_MAP " + mapping(rr_addr))
        if not state["armed"] and rr_addr:
            try:
                ReadBreak(rr_addr)
                state["armed"] = True
                note("WATCH_RR 0x%x" % rr_addr)
            except gdb.error as exc:
                note("WATCH_FAIL 0x%x %r" % (rr_addr, exc))


def make_break(address, label):
    bp = gdb.Breakpoint(address, internal=False)
    bp.condition = MEM_COND
    bp.enabled = False
    gdb.execute("commands %d\nsilent\npython onig_hit(%r)\ncontinue\nend"
                % (bp.number, label))
    return bp


pre_bp = make_break("*(&match_at + 2410)", "BEFORE")
post_bp = make_break("*(&match_at + 2464)", "AFTER")


class EntryBreak(gdb.Breakpoint):
    def __init__(self):
        super().__init__("match_at", internal=True)
        self.enabled = False

    def stop(self):
        try:
            state["reg"] = int(gdb.parse_and_eval("(long)reg"))
        except Exception:
            pass
        return False


entry_bp = EntryBreak()


class CompileBreak(gdb.Breakpoint):
    def __init__(self):
        super().__init__("rb_reg_initialize", internal=True)

    def stop(self):
        try:
            length = int(gdb.parse_and_eval("len"))
        except gdb.error:
            return False
        if length <= 300000:
            return False
        note("ARM len=%d" % length)
        gdb.execute("enable %d %d" % (pre_bp.number, post_bp.number))
        entry_bp.enabled = True
        return False


gdb.events.stop.connect(lambda event: None)
CompileBreak()
gdb.execute("run")
