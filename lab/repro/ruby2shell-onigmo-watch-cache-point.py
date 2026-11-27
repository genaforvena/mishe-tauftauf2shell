# W310: census the OOB `reg->repeat_range[outer_repeat_mem]` metadata read in
# `find_cache_point` (regexec.c:2242, from CHECK_MATCH_CACHE at regexec.c:2605).
# W306 closed the repeat-range reads in `match_at`; this watches the other
# consumer named on the wall. At the armed BEFORE site dump the outer repeat
# ID, the RepeatRange address/lower/upper, its /proc maps owner, the derived
# repeat_stk slot, and arm a READ watchpoint on the 8-byte slot for backtraces.
# Native gdb `commands` conditions gate the site: Python stop() overrides gdb
# conditions (measured W302). `reg` is cached at find_cache_point entry because
# it may optimize out at the BEFORE site (W306 measured the same for match_at).
import gdb
import os

state = {
    "outer": None,
    "range_addr": None,
    "reg": None,
    "reads": 0,
    "gates": 0,
    "entries": 0,
    "seen_pre": set(),
    "armed": False,
}
MAX_READS = int(os.environ.get("RUBY2SHELL_ONIGMO_MAX_READS", "5"))
RAW_OUTER_COND = os.environ.get(
    "RUBY2SHELL_ONIGMO_MEM_COND", "cache_opcode->outer_repeat_mem == -32767"
).strip()
OUTER_COND = (RAW_OUTER_COND.replace("mem", "cache_opcode->outer_repeat_mem")
              if RAW_OUTER_COND.startswith("mem") else RAW_OUTER_COND)


def note(text):
    print("ONIG_CP " + text, flush=True)


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
            note("READ %d addr=0x%x qword=0x%x lower=%d upper=%d outer=%d"
                 % (state["reads"], self.address, qword & 0xFFFFFFFFFFFFFFFF,
                    lo, hi, state["outer"]))
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
        outer = int(gdb.parse_and_eval("cache_opcode->outer_repeat_mem"))
    except Exception as exc:
        note("NO_OUTER %s %r" % (label, exc))
        return
    state["outer"] = outer
    reg = reg_value()
    try:
        rr_addr = int(gdb.parse_and_eval("(long)&reg->repeat_range[outer_repeat_mem]"
                                         .replace("outer_repeat_mem", str(outer))))
    except Exception:
        try:
            off = int(gdb.parse_and_eval("(long)&((regex_t *)0)->repeat_range"))
            rr_addr = reg + off + outer * 8
        except Exception as exc:
            note("RR_ADDR_FAIL %s %r" % (label, exc))
            return
    state["range_addr"] = rr_addr
    try:
        size = int(gdb.parse_and_eval("sizeof(OnigRepeatRange)"))
    except Exception:
        size = 8
    try:
        lower = int(gdb.parse_and_eval("(int)reg->repeat_range[%d].lower" % outer))
        upper = int(gdb.parse_and_eval("(int)reg->repeat_range[%d].upper" % outer))
        vals = "lower=%d upper=%d" % (lower, upper)
    except Exception as exc:
        vals = "vals_UNAVAILABLE %r" % (exc,)
    try:
        cp = int(gdb.parse_and_eval("cache_opcode->cache_point"))
        at = int(gdb.parse_and_eval("cache_opcode->num_cache_points_at_outer_repeat"))
        inr = int(gdb.parse_and_eval("cache_opcode->num_cache_points_in_outer_repeat"))
        meta = "cache_point=%d at=%d in=%d" % (cp, at, inr)
    except Exception as exc:
        meta = "meta_UNAVAILABLE %r" % (exc,)
    try:
        slot = int(gdb.parse_and_eval("(long)&repeat_stk[%d]" % outer))
        val = int(gdb.parse_and_eval("repeat_stk[%d]" % outer))
        stkmeta = "repeat_stk[%d]=0x%x(%s)" % (outer, val & 0xFFFFFFFFFFFFFFFF,
                                               kind(val))
    except Exception as exc:
        slot = None
        stkmeta = "stk_UNAVAILABLE %r" % (exc,)
    note("%s outer=%d reg=0x%x(%s) rr=0x%x(%s) delta=%d size=%d %s %s %s%s"
         % (label, outer, reg & 0xFFFFFFFFFFFFFFFF, kind(reg),
            rr_addr & 0xFFFFFFFFFFFFFFFF, kind(rr_addr), rr_addr - reg, size,
            vals, meta, stkmeta, "" if slot is None else " slot=0x%x" % slot))
    if label == "BEFORE" and rr_addr not in state["seen_pre"]:
        state["seen_pre"].add(rr_addr)
        note("RR_MAP " + mapping(rr_addr))
        if not state["armed"] and rr_addr:
            try:
                ReadBreak(rr_addr)
                state["armed"] = True
                note("WATCH_RR 0x%x" % rr_addr)
            except gdb.error as exc:
                note("WATCH_FAIL 0x%x %r" % (rr_addr, exc))


# match_at+1126 (0x161396) is the comparison `num_fails >= (end-str) *
# num_cache_opcodes` that gates cache activation (regexec.c:4122). Log it so a
# no-hit result can distinguish "no cache opcode at p" from "cache never on".
GATE_LOG = int(os.environ.get("RUBY2SHELL_ONIGMO_GATE_LOG", "8"))
gate_bp = gdb.Breakpoint("*(&match_at + 1126)", internal=False)
gate_bp.enabled = False
gdb.execute("commands %d\nsilent\npython gate_hit()\ncontinue\nend" % gate_bp.number)


def gate_hit():
    if state["gates"] >= GATE_LOG:
        return
    state["gates"] += 1
    try:
        fails = int(gdb.parse_and_eval("$rax"))
        threshold = int(gdb.parse_and_eval("$rsi"))
        status = int(gdb.parse_and_eval("$ecx"))
        nops = int(gdb.parse_and_eval("*(long*)($r13 + 0x60)"))
        note("GATE %d num_fails=%d threshold=%d status=%d num_cache_opcodes=%d"
             % (state["gates"], fails, threshold, status, nops))
    except Exception as exc:
        note("GATE_FAIL %d %r" % (state["gates"], exc))

# regexec.c:2242 is find_cache_point+168 in the pinned 3.4.11 plain build
# (checked with `info line regexec.c:2242`); the wall names it match_cache_point.
cp_bp = gdb.Breakpoint("*(&find_cache_point + 168)", internal=False)
cp_bp.condition = OUTER_COND
cp_bp.enabled = False
gdb.execute("commands %d\nsilent\npython onig_hit('BEFORE')\ncontinue\nend"
            % cp_bp.number)


def entry_hit():
    state["entries"] += 1
    if state["entries"] in (1, 100, 1000, 10000):
        note("ENTRY %d" % state["entries"])
    try:
        state["reg"] = int(gdb.parse_and_eval("(long)reg"))
    except Exception:
        pass


entry_bp = gdb.Breakpoint("find_cache_point", internal=False)
entry_bp.enabled = False
gdb.execute("commands %d\nsilent\npython entry_hit()\ncontinue\nend" % entry_bp.number)


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
        note("ARM len=%d cond=%s" % (length, OUTER_COND))
        cp_bp.enabled = True
        gate_bp.enabled = True
        entry_bp.enabled = True
        return False


CompileBreak()
gdb.execute("run")
