# W361: minimal read-only observer for the terminal path of the 49-map JIF.
# Only the inflate entry and return software breakpoints; no loader breakpoints,
# no hardware watchpoints, and the signal handler reads no registers (the full
# observer hit a GDB internal fatal error on the terminal SIGSEGV).
set pagination off
set confirm off
set print thread-events off
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w361-min.log")
AVAIL = int(os.environ.get("W361_AVAIL", "0x8000000c"), 0)
_log = open(LOG_PATH, "w", buffering=1)
_state = {"strm": None, "idx": None}


def emit(msg):
    print(str(msg))
    _log.write(str(msg) + "\n")


def reg(name):
    return int(gdb.parse_and_eval("$" + name))


class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        strm = _state["strm"]
        try:
            total = int(gdb.parse_and_eval("*(unsigned long*)(%d+40)" % strm))
            out = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            emit("W361-MIN INFLATE_RETURN ret=%#x total_out=%#x next_out=%#x "
                 "avail_out=%#x" % (reg("rax"), total, out, avail))
        except Exception as e:
            emit("W361-MIN RETURN ERROR %s" % e)
        self.delete()
        return False


class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = reg("rdi")
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != AVAIL:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            _state["idx"] = idx
            _state["strm"] = strm
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            emit("W361-MIN PRE avail=%#x idx=%#x ret=%#x" % (avail, idx, ret))
            RetBP(ret)
        except Exception as e:
            emit("W361-MIN INFLATE ERROR %s" % e)
        return False


def on_stop(ev):
    if isinstance(ev, gdb.SignalEvent) and ev.stop_signal in (
            "SIGSEGV", "SIGABRT", "SIGBUS"):
        emit("W361-MIN SIGNAL %s" % ev.stop_signal)


gdb.events.stop.connect(on_stop)
InflateBP("inflate")
end
run
