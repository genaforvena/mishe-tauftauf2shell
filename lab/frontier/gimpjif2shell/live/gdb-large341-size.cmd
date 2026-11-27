# W341: large geometry with the adjacent free chunk's size word preserved.
# Arm a WRITE watch on that word (idx+65544) to see whether a live allocator
# consumes the corrupted free chunk after the pinned inflate returns.
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
python
import gdb, os

LOG_PATH = os.environ.get("W337_LOG", "/tmp/w341-size.log")
_log = open(LOG_PATH, "w", buffering=1)
state = {"idx": 0}

def emit(msg):
    text = str(msg)
    print(text)
    _log.write(text + "\n")

def word(addr):
    return int(gdb.parse_and_eval("*(unsigned long*)%d" % addr))

class WatchBP(gdb.Breakpoint):
    def __init__(self, tag, addr, wp):
        super(WatchBP, self).__init__("*(unsigned long*)%d" % addr,
                                      gdb.BP_WATCHPOINT, wp, internal=True)
        self.tag = tag

    def stop(self):
        emit("W341 WATCH %s HIT pc=%#x" %
             (self.tag, int(gdb.parse_and_eval("$pc"))))
        gdb.execute("bt 8")
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(RetBP, self).__init__("*%#x" % addr, internal=True)

    def stop(self):
        idx = state["idx"]
        emit("W341 POST idx=%#x free_size=%#x free_fd=%#x free_bk=%#x" %
             (idx, word(idx + 65544), word(idx + 65552), word(idx + 65560)))
        try:
            WatchBP("free_size_write", idx + 65544, gdb.WP_WRITE)
            WatchBP("free_fd_read", idx + 65552, gdb.WP_READ)
            emit("W341 WATCH armed free_size_write free_fd_read")
        except Exception as e:
            emit("W341 WATCH ARM FAILED %s" % e)
        self.delete()
        return False

class InflateBP(gdb.Breakpoint):
    def stop(self):
        try:
            strm = int(gdb.parse_and_eval("$rdi"))
            avail = int(gdb.parse_and_eval("*(unsigned int*)(%d+32)" % strm))
            if avail != 2147516415:
                return False
            idx = int(gdb.parse_and_eval("*(void**)(%d+24)" % strm))
            ret = int(gdb.parse_and_eval("*(unsigned long*)$rsp"))
            state["idx"] = idx
            emit("W341 PRE avail=%#x idx=%#x" % (avail, idx))
            RetBP(ret)
        except Exception as e:
            emit("W341 INFLATE ERROR %s" % e)
        return False

InflateBP("inflate")
end
run
