# Gated gdb watch for the W304 deeper wrapped repeat-ID sweep (IDs -17..-64).
# Native conditions do the filtering: Python stop() overrides bypass gdb
# conditions (measured in W302), so only commands blocks call in.
# Logs the qword at each BEFORE/AFTER write site, flags pointer-like PRE values,
# and watches up to three distinct targets for later reads (a live consumer
# shows a read backtrace).
import gdb
import os

state = {
    "last": "none",
    "watched": set(),
    "reads": 0,
    "seen_pre": set(),
    "ptr_notes": 0,
}
marker = os.environ.get("RUBY2SHELL_ONIGMO_SECOND_MARKER")
marked = False
MAX_READS = int(os.environ.get("RUBY2SHELL_ONIGMO_MAX_READS", "5"))
MAX_PTR_NOTES = 12


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


class ReadBreak(gdb.Breakpoint):
    def __init__(self, address):
        super().__init__("*0x%x" % address, type=gdb.BP_WATCHPOINT,
                         wp_class=gdb.WP_READ, internal=True)
        self.address = address

    def stop(self):
        if state["reads"] >= MAX_READS:
            self.delete()
            return False
        state["reads"] += 1
        slot = int(gdb.parse_and_eval("(long)*(void **)0x%x" % self.address))
        note("READ %d target=0x%x slot=0x%x(%s) %s"
             % (state["reads"], self.address, slot, kind(slot), state["last"]))
        note("READ_BT " + gdb.execute("bt 3", to_string=True).replace("\n", " | "))
        return False


def onig_hit(label):
    global marked
    mem = int(gdb.parse_and_eval("mem"))
    target = int(gdb.parse_and_eval("(long)&repeat_stk[mem]"))
    base = int(gdb.parse_and_eval("(long)alloca_base"))
    slot = int(gdb.parse_and_eval("(long)repeat_stk[mem]"))
    state["last"] = "mem=%d target=0x%x base=0x%x delta=%d slot=0x%x(%s) slot_dec=%d" % (
        mem, target, base, target - base, slot, kind(slot), slot)
    note("%s %s" % (label, state["last"]))
    if label == "BEFORE" and target not in state["seen_pre"]:
        state["seen_pre"].add(target)
        note("PRE k=%d %s" % (-mem, state["last"]))
    if label == "BEFORE" and kind(slot) in ("stack", "mmap", "pie"):
        if state["ptr_notes"] < MAX_PTR_NOTES:
            state["ptr_notes"] += 1
            note("PTR k=%d %s" % (-mem, state["last"]))
    if target not in state["watched"] and len(state["watched"]) < 3:
        try:
            state["watched"].add(target)
            ReadBreak(target)
            note("WATCH %s" % state["last"])
        except gdb.error as exc:
            note("WATCH_FAIL %r" % exc)
    if marker and not marked and os.path.exists(marker):
        marked = True
        note("SECOND_MARK")


def make_break(address, label):
    bp = gdb.Breakpoint(address, internal=False)
    bp.condition = "mem < 0 && mem > -129"
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
