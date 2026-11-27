# W355: read-only observer for the W353 JIF's live loader consumer.
# Breaks on do_lookup_x entry (file offset 0xa220) and the GNU-hash table
# load (0xa2e1). No memory or register is written by GDB; it only inserts
# software breakpoints, reads state and writes W337_LOG.
set pagination off
set confirm off
set print thread-events off
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w355-entry.log")
_log = open(LOG_PATH, "w", buffering=1)
ENTRY_OFF = 0xa220
TABLE_OFF = 0xa2e1
MAX_ENTRIES = 16


def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")


def reg(name):
    return int(gdb.parse_and_eval("$" + name))


def maps(pid):
    try:
        with open("/proc/%d/maps" % pid) as f:
            return [line.rstrip() for line in f]
    except Exception:
        return []


def ld_base(pid):
    for line in maps(pid):
        parts = line.split()
        if len(parts) >= 6 and parts[-1].endswith("ld-linux-x86-64.so.2") \
                and parts[1] == "r--p":
            return int(parts[0].split("-")[0], 16)
    return None


class EntryBP(gdb.Breakpoint):
    count = 0

    def __init__(self, addr):
        super(EntryBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        EntryBP.count += 1
        if EntryBP.count > MAX_ENTRIES:
            self.delete()
            return False
        emit("W355 ENTRY n=%d pc=%#x rdi=%#x rsi=%#x rdx=%#x rcx=%#x r8=%#x r9=%#x"
             % (EntryBP.count, reg("pc"), reg("rdi"), reg("rsi"), reg("rdx"),
                reg("rcx"), reg("r8"), reg("r9")))
        emit("W355 ENTRY-STACK n=%d i=%#x ver=%#x flags=%#x skip=%#x tc=%#x umap=%#x"
             % (EntryBP.count,
                int(gdb.parse_and_eval("*(unsigned long*)($rsp+8)")),
                int(gdb.parse_and_eval("*(unsigned long*)($rsp+16)")),
                int(gdb.parse_and_eval("*(unsigned long*)($rsp+24)")),
                int(gdb.parse_and_eval("*(unsigned long*)($rsp+32)")),
                int(gdb.parse_and_eval("*(unsigned long*)($rsp+40)")),
                int(gdb.parse_and_eval("*(unsigned long*)($rsp+48)"))))
        try:
            emit("W355 ENTRY-NAME n=%d %s" %
                 (EntryBP.count, gdb.parse_and_eval("(char*)$rdi").string()))
        except Exception as e:
            emit("W355 ENTRY-NAME ERROR %s" % e)
        return False


class TableBP(gdb.Breakpoint):
    count = 0

    def __init__(self, addr):
        super(TableBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        TableBP.count += 1
        if TableBP.count > 120:
            self.delete()
            return False
        rbx = reg("rbx")
        emit("W355 TABLE n=%d pc=%#x rbx=%#x rdx=%#x rax=%#x r12=%#x"
             % (TableBP.count, reg("pc"), rbx, reg("rdx"), reg("rax"),
                reg("r12")))
        if rbx == 0x5555556c0240 or reg("rdx") not in (
                0x55555556c078, 0x4040404040404040):
            for off, name, ctype in (
                    (0x32c, "l_nbuckets", "unsigned int"),
                    (0x330, "l_gnu_bitmask_idxbits", "unsigned int"),
                    (0x338, "l_gnu_bitmask", "unsigned long"),
                    (0x340, "l_gnu_buckets", "unsigned long"),
                    (0x348, "l_gnu_chain_zero", "unsigned long")):
                try:
                    value = int(gdb.parse_and_eval("*(%s*)($rbx+%#x)" %
                                                   (ctype, off)))
                    emit("W355 FIELD n=%d %s=%#x" %
                         (TableBP.count, name, value))
                except Exception as e:
                    emit("W355 FIELD ERROR %s" % e)
        return False


class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = reg("rdi")
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483650:
                return False
            emit("W355 PRE avail=%#x idx=%#x" %
                 (avail, int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))))
            base = ld_base(gdb.selected_inferior().pid)
            emit("W355 LD base=%s" % ("%#x" % base if base else "UNKNOWN"))
            if base:
                EntryBP(base + ENTRY_OFF)
                TableBP(base + TABLE_OFF)
        except Exception as e:
            emit("W355 INFLATE ERROR %s" % e)
        return False


def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    emit("W355 SIGNAL %s pc=%#x rax=%#x rbx=%#x rdx=%#x" %
         (ev.stop_signal, reg("pc"), reg("rax"), reg("rbx"), reg("rdx")))


gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
