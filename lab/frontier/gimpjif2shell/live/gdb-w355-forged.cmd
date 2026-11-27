# W355: read-only observer for the forged-link_map JIF. Logs the exact
# writes reached after a chosen GNU-hash table read. No memory or register
# is written by GDB; only software breakpoints and its own log file.
set pagination off
set confirm off
set print thread-events off
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w355-forged.log")
_log = open(LOG_PATH, "w", buffering=1)


def emit(msg):
    print(str(msg))
    _log.write(str(msg) + "\n")


def reg(name):
    return int(gdb.parse_and_eval("$" + name))


def maps(pid):
    with open("/proc/%d/maps" % pid) as f:
        return [line.rstrip() for line in f]


def ld_base(pid):
    for line in maps(pid):
        parts = line.split()
        if len(parts) >= 6 and parts[-1].endswith("ld-linux-x86-64.so.2") \
                and parts[1] == "r--p":
            return int(parts[0].split("-")[0], 16)
    return None


class Watch(gdb.Breakpoint):
    def __init__(self, addr, label, limit=24):
        super(Watch, self).__init__("*%#x" % addr, internal=True)
        self.label = label
        self.limit = limit
        self.count = 0

    def stop(self):
        self.count += 1
        if self.count > self.limit:
            self.delete()
            return False
        if self.label == "ENTRY":
            emit("W355F %s n=%d name=%s hash=%#x scope=%#x" %
                 (self.label, self.count,
                  gdb.parse_and_eval("(char*)$rdi").string(), reg("rsi"),
                  reg("r9")))
        elif self.label == "MATCH":
            emit("W355F %s n=%d rdi=%#x r9=%#x st_name=%#x map=%#x" %
                 (self.label, self.count, reg("rdi"), reg("r9"),
                  int(gdb.parse_and_eval("*(unsigned int*)($r9)")),
                  int(gdb.parse_and_eval("*(unsigned long*)($rsp+40)"))))
        elif self.label == "LUSED":
            emit("W355F %s n=%d map=%#x l_used_before=%#x" %
                 (self.label, self.count, reg("r15"),
                  int(gdb.parse_and_eval("*(unsigned int*)($r15+0x414)"))))
        elif self.label == "GOT":
            emit("W355F %s n=%d rel_addr=%#x value=%#x" %
                 (self.label, self.count, reg("r13"), reg("rax")))
        elif self.label == "TABLE":
            emit("W355F %s n=%d rbx=%#x rdx=%#x rax=%#x hash=%#x" %
                 (self.label, self.count, reg("rbx"), reg("rdx"), reg("rax"),
                  reg("r12")))
        else:
            emit("W355F %s n=%d pc=%#x" % (self.label, self.count, reg("pc")))
        return False


watches = []


class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = reg("rdi")
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147483650:
                return False
            emit("W355F PRE avail=%#x idx=%#x" %
                 (avail, int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))))
            base = ld_base(gdb.selected_inferior().pid)
            emit("W355F LD base=%s" % ("%#x" % base if base else "UNKNOWN"))
            if base:
                for off, label in ((0xa220, "ENTRY"), (0xa0a0, "MATCH"),
                                   (0xa2e1, "TABLE"), (0xb200, "LUSED"),
                                   (0x11257, "GOT")):
                    watches.append(Watch(base + off, label))
        except Exception as e:
            emit("W355F INFLATE ERROR %s" % e)
        return False


def on_stop(ev):
    if isinstance(ev, gdb.SignalEvent) and ev.stop_signal in (
            "SIGSEGV", "SIGABRT", "SIGBUS"):
        emit("W355F SIGNAL %s pc=%#x rax=%#x rbx=%#x" %
             (ev.stop_signal, reg("pc"), reg("rax"), reg("rbx")))


gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
