# Gated gdb watch for the W303 negative repeat-ID sweep.
# Native conditions do the filtering: Python stop() overrides bypass gdb
# breakpoint conditions (measured in W302), so only commands blocks call in.
# Logs the slot value at the BEFORE/AFTER write sites and watches the first
# distinct target for later reads (a live consumer shows a read backtrace).
import gdb
import os

state = {"last": "none", "watched": set(), "reads": 0}
marker = os.environ.get("RUBY2SHELL_ONIGMO_SECOND_MARKER")
marked = False
MAX_READS = int(os.environ.get("RUBY2SHELL_ONIGMO_MAX_READS", "5"))


def note(text):
    print("ONIG_NEG " + text, flush=True)


def kind(value):
    if 0x700000000000 <= value < 0x800000000000:
        return "stackptr"
    if 0x500000000000 <= value < 0x600000000000:
        return "codeptr"
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
        note("READ %d target=0x%x %s" % (state["reads"], self.address, state["last"]))
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
    if target not in state["watched"] and len(state["watched"]) < 3:
        state["watched"].add(target)
        ReadBreak(target)
        note("WATCH %s" % state["last"])
    if marker and not marked and os.path.exists(marker):
        marked = True
        note("SECOND_MARK")


def make_break(address, label):
    bp = gdb.Breakpoint(address, internal=False)
    bp.condition = "mem < 0 && mem > -33"
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
