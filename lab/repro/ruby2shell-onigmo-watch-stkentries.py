# Gated gdb census of the positive repeat_stk entries and the Onigmo stack
# node selected by the wire-visible wrapped repeat ID (W305). Native conditions
# filter: Python stop() overrides bypass gdb conditions (measured in W302), so
# only commands blocks call in. At the first armed BEFORE hit, and again at the
# first consumed read, dump `si` and repeat_stk[0..31], flag pointer-like
# entries, and arm read watchpoints on up to two of them. The wrapped write
# target is watched once for context (its reader is match_at regexec.c:3877).
# `mem` and `stk_base` are cached at the write breakpoint: both optimize out at
# the watchpoint stop where the consumed read is observed.
import gdb
import os

state = {
    "last": "none",
    "watched": set(),
    "write_watched": False,
    "reads": 0,
    "seen_pre": set(),
    "censused": set(),
    "mem": None,
    "stk_base": None,
}
marker = os.environ.get("RUBY2SHELL_ONIGMO_SECOND_MARKER")
marked = False
MAX_READS = int(os.environ.get("RUBY2SHELL_ONIGMO_MAX_READS", "5"))
MEM_COND = os.environ.get("RUBY2SHELL_ONIGMO_MEM_COND", "mem < 0 && mem > -129")
MAX_ENTRY_WATCHES = 2
CENSUS_N = 32


def note(text):
    print("ONIG_DEEP " + text, flush=True)


def kind(value):
    u = value & 0xFFFFFFFFFFFFFFFF
    if 0x7FFC00000000 <= u < 0x800000000000:
        return "stack"
    if 0x7F0000000000 <= u < 0x7FFC00000000:
        return "mmap"
    if 0x550000000000 <= u < 0x560000000000:
        return "pie"  # PIE code or brk heap under ASLR-off
    if value == 0:
        return "zero"
    if -1000000 < value < 1000000:
        return "small"
    return "other"


def dump_entries(label):
    if label in state["censused"]:
        return []
    state["censused"].add(label)
    vals = []
    ptrs = []
    for i in range(CENSUS_N):
        try:
            v = int(gdb.parse_and_eval("(long)repeat_stk[%d]" % i))
        except gdb.error as exc:
            note("STK_FAIL %s i=%d %r" % (label, i, exc))
            return []
        vals.append(v)
        k = kind(v)
        if k in ("stack", "mmap", "pie"):
            ptrs.append((i, v, k))
    note("STK_CENSUS %s vals=%s" % (
        label, " ".join("0x%x" % (v & 0xFFFFFFFFFFFFFFFF) for v in vals)))
    for i, v, k in ptrs:
        note("STK_PTR %s i=%d %s 0x%x" % (label, i, k, v & 0xFFFFFFFFFFFFFFFF))
    try:
        si = int(gdb.parse_and_eval("si"))
        note("SI %s si=%d(%s)" % (label, si, kind(si)))
    except Exception as exc:
        note("SI %s unavailable %r" % (label, exc))
    return ptrs


def dump_stk_target(label):
    try:
        mem = state["mem"]
        si = int(gdb.parse_and_eval("(long)repeat_stk[%d]" % mem))
        base = state["stk_base"]
        try:
            size = int(gdb.parse_and_eval("sizeof(OnigStackType)"))
        except Exception:
            size = 48
        node = base + si * size
        qwords = [int(gdb.parse_and_eval("(long)*(void **)(0x%x + %d)" % (node, off)))
                  for off in (0, 8, 16, 24, 32, 40)]
        note("STK_NODE %s mem=%d si=%d base=0x%x node=0x%x size=%d qwords=%s kinds=%s"
             % (label, mem, si, base, node, size,
                " ".join("0x%x" % (q & 0xFFFFFFFFFFFFFFFF) for q in qwords),
                " ".join(kind(q) for q in qwords)))
    except Exception as exc:
        note("STK_NODE %s unavailable %r" % (label, exc))


class ReadBreak(gdb.Breakpoint):
    def __init__(self, address, tag):
        super().__init__("*0x%x" % address, type=gdb.BP_WATCHPOINT,
                         wp_class=gdb.WP_READ, internal=True)
        self.address = address
        self.tag = tag

    def stop(self):
        if state["reads"] >= MAX_READS:
            self.delete()
            return False
        state["reads"] += 1
        slot = int(gdb.parse_and_eval("(long)*(void **)0x%x" % self.address))
        note("READ %d target=0x%x tag=%s slot=0x%x(%s) %s"
             % (state["reads"], self.address, self.tag, slot, kind(slot), state["last"]))
        note("READ_BT " + gdb.execute("bt 3", to_string=True).replace("\n", " | "))
        if self.tag == "write":
            dump_entries("READ")
            dump_stk_target("READ")
        return False


def watch_ptrs(label, ptrs):
    for i, v, k in ptrs:
        addr = v & 0xFFFFFFFFFFFFFFFF
        if addr in state["watched"]:
            continue
        if len(state["watched"]) >= MAX_ENTRY_WATCHES:
            break
        try:
            state["watched"].add(addr)
            ReadBreak(addr, "stk[%d]" % i)
            note("WATCH_STK %s i=%d %s 0x%x" % (label, i, k, addr))
        except gdb.error as exc:
            note("WATCH_FAIL %s i=%d %r" % (label, i, exc))


def onig_hit(label):
    global marked
    mem = int(gdb.parse_and_eval("mem"))
    state["mem"] = mem
    try:
        state["stk_base"] = int(gdb.parse_and_eval("(long)stk_base"))
    except Exception:
        pass
    target = int(gdb.parse_and_eval("(long)&repeat_stk[mem]"))
    base = int(gdb.parse_and_eval("(long)alloca_base"))
    slot = int(gdb.parse_and_eval("(long)repeat_stk[mem]"))
    state["last"] = "mem=%d target=0x%x base=0x%x delta=%d slot=0x%x(%s) slot_dec=%d" % (
        mem, target, base, target - base, slot, kind(slot), slot)
    note("%s %s" % (label, state["last"]))
    if label == "BEFORE" and target not in state["seen_pre"]:
        state["seen_pre"].add(target)
        note("PRE k=%d %s" % (-mem, state["last"]))
        watch_ptrs("BEFORE", dump_entries("BEFORE"))
    if label == "BEFORE" and not state["write_watched"]:
        try:
            state["write_watched"] = True
            ReadBreak(target, "write")
            note("WATCH_WRITE %s" % state["last"])
        except gdb.error as exc:
            note("WATCH_FAIL write %r" % exc)
    if marker and not marked and os.path.exists(marker):
        marked = True
        note("SECOND_MARK")


def make_break(address, label):
    bp = gdb.Breakpoint(address, internal=False)
    bp.condition = MEM_COND
    bp.enabled = False
    gdb.execute("commands %d\nsilent\npython onig_hit(%r)\ncontinue\nend"
                % (bp.number, label))
    return bp


pre_bp = make_break("*(&match_at + 2410)", "BEFORE")
post_bp = make_break("*(&match_at + 2464)", "AFTER")


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
        return False


def on_stop(event):
    if not isinstance(event, gdb.SignalEvent):
        return
    note("SIGNAL %s details=%s" % (event.stop_signal, event.details))
    note("LAST_WRITE " + state["last"])
    try:
        addr = int(gdb.parse_and_eval("$_siginfo._sifields._sigfault.si_addr"))
        note("SI_ADDR=0x%x" % addr)
    except Exception as exc:
        note("SI_ADDR unavailable %r" % exc)
    try:
        note("SI_BT " + gdb.execute("bt 6", to_string=True).replace("\n", " | "))
    except Exception as exc:
        note("SI_BT unavailable %r" % exc)


gdb.events.stop.connect(on_stop)
CompileBreak()
gdb.execute("run")
