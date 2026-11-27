# gdb watch for the W300 fault case of the pinned 3.4.11 repeat-ID write.
# Python stop() overrides bypass gdb breakpoint conditions, so the two write
# sites are plain conditional breakpoints with command lists; Python is used
# only for arming, marker attribution and SIGSEGV capture.
import gdb
import os

state = {"mark": False, "last": "none"}
marker = os.environ.get("RUBY2SHELL_ONIGMO_SECOND_MARKER")


def note(text):
    print("ONIG_FAULT " + text, flush=True)

def onig_write():
    mem = int(gdb.parse_and_eval("mem"))
    target = int(gdb.parse_and_eval("&repeat_stk[mem]"))
    base = int(gdb.parse_and_eval("alloca_base"))
    state["last"] = "mem=%d target=0x%x base=0x%x delta=%d" % (
        mem, target, base, target - base)


def onig_hit():
    onig_write()
    if marker and not state["mark"] and os.path.exists(marker):
        state["mark"] = True
        note("SECOND_MARK")


def make_break(address, label):
    bp = gdb.Breakpoint(address, internal=False)
    bp.condition = "mem < 0"
    bp.enabled = False
    fmt = ("printf \"ONIG_FAULT %s mem=%%d target=%%p base=%%p delta=%%ld "
           "slot=%%ld\\n\", mem, &repeat_stk[mem], alloca_base, "
           "(long)((char *)&repeat_stk[mem] - (char *)alloca_base), "
           "(long)repeat_stk[mem]\n") % label
    gdb.execute("commands %d\nsilent\npython onig_hit()\n%scontinue\nend"
                % (bp.number, fmt))
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
        note("SI_REGS " + gdb.execute("info registers rip rsp", to_string=True).replace("\n", " | "))
    except Exception as exc:
        note("SI_REGS unavailable %r" % exc)
    try:
        note("SI_BT " + gdb.execute("bt 8", to_string=True).replace("\n", " | "))
    except Exception as exc:
        note("SI_BT unavailable %r" % exc)


gdb.events.stop.connect(on_stop)
CompileBreak()
gdb.execute("run")
