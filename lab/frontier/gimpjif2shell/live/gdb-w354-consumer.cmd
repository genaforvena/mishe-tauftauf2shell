# W354: read-only identification of the W349/W352 third-stage consumer.
# The fixed PCs come from the existing W352 observer. No memory, register or
# plug-in byte is written; GDB writes only W337_LOG.
set pagination off
set confirm off
set print thread-events off
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w354-consumer.log")
_log = open(LOG_PATH, "w", buffering=1)

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

def maps(pid):
    try:
        with open("/proc/%d/maps" % pid) as f:
            return [line.rstrip() for line in f]
    except Exception:
        return []

def classify(addr, ranges):
    for line in ranges:
        parts = line.split()
        if len(parts) < 2 or "-" not in parts[0]:
            continue
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        if lo <= addr < hi:
            return line
    return "unmapped"

class ConsumerBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(ConsumerBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        pc = int(gdb.parse_and_eval("$pc"))
        ranges = maps(gdb.selected_inferior().pid)
        emit("W354 CONSUMER pc=%#x mapping=%s" % (pc, classify(pc, ranges)))
        emit("W354 OPERANDS rdi=%#x r12=%#x rbx=%#x r14=%#x" %
             (int(gdb.parse_and_eval("$rdi")),
              int(gdb.parse_and_eval("$r12")),
              int(gdb.parse_and_eval("$rbx")),
              int(gdb.parse_and_eval("$r14"))))
        try:
            emit("W354 UNDEF_NAME=%s" %
                 gdb.parse_and_eval("(char*)$rdi").string())
        except Exception as e:
            emit("W354 UNDEF_NAME ERROR %s" % e)
        for off, name, ctype in ((0x32c, "l_nbuckets", "unsigned int"),
                                 (0x330, "l_gnu_bitmask_idxbits", "unsigned int"),
                                 (0x338, "l_gnu_bitmask", "unsigned long")):
            try:
                value = int(gdb.parse_and_eval("*(%s*)($rbx+%#x)" %
                                               (ctype, off)))
                emit("W354 FIELD %s=%#x" % (name, value))
            except Exception as e:
                emit("W354 FIELD %s ERROR %s" % (name, e))
        for command in ("info symbol $pc", "x/12i $pc-32", "bt 16"):
            try:
                emit("W354 %s\n%s" % (command, gdb.execute(command, to_string=True)))
            except Exception as e:
                emit("W354 %s ERROR %s" % (command, e))
        self.delete()
        return False

class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483650:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            emit("W354 PRE avail=%#x idx=%#x" % (avail, idx))
            ConsumerBP(0x7ffff7fd12e1)
        except Exception as e:
            emit("W354 INFLATE ERROR %s" % e)
        return False

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    emit("W354 SIGNAL %s pc=%#x rax=%#x rbx=%#x rdx=%#x r14=%#x" %
         (ev.stop_signal, int(gdb.parse_and_eval("$pc")),
          int(gdb.parse_and_eval("$rax")),
          int(gdb.parse_and_eval("$rbx")),
          int(gdb.parse_and_eval("$rdx")),
          int(gdb.parse_and_eval("$r14"))))
    try:
        emit("W354 SIGNAL INS\n%s" %
             gdb.execute("x/8i $pc-16", to_string=True))
    except Exception as e:
        emit("W354 SIGNAL INS ERROR %s" % e)

gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
