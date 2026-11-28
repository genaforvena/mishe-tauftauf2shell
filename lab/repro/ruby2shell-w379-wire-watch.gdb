# W379: watch BOTH rb_str_casemap to_end addresses in ONE wire-fed Ruby
# process (CVE-2026-132825). Observability only: hardware WRITE watchpoints,
# no debugger memory writes, no request-path middleware. Derived from the
# committed W368 script ruby2shell-twofold-watch-all.gdb.
#
# Run from the repository root via ruby2shell-w379-wire-watch.sh, or directly:
#   gdb -q -batch -x lab/repro/ruby2shell-w379-wire-watch.gdb --args \
#       lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#       lab/repro/ruby2shell-stock-baseline.ru
# Environment: R2S_W379_MIN_CAPA (default 40), R2S_W379_MAX_WATCH (default 4).
set pagination off
set confirm off
set breakpoint pending on
python
import os, re, gdb

MIN_CAPA = int(os.environ.get("R2S_W379_MIN_CAPA", "40"))
MAX_WATCH = int(os.environ.get("R2S_W379_MAX_WATCH", "4"))
callno = 0
active_call = 0
foldno = 0
traps = []
maps_cache = None


def rd(addr, n):
    try:
        return bytes(gdb.selected_inferior().read_memory(int(addr), n))
    except Exception:
        return None


def region(addr):
    global maps_cache
    if maps_cache is None:
        maps_cache = []
        try:
            txt = gdb.execute("info proc mappings", to_string=True)
        except Exception:
            txt = ""
        for line in txt.splitlines():
            m = re.match(r"^\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s*(.*)$", line)
            if m:
                maps_cache.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3).strip()))
    for lo, hi, nm in maps_cache:
        if lo <= addr < hi:
            return "%#x-%#x:%s" % (lo, hi, nm)
    return "UNKNOWN"


def dump(addr, before=24, after=24):
    b = rd(int(addr) - before, before + after)
    if b is None:
        return "UNREADABLE"
    return " ".join("%+d:%s" % (i - before, b[i:i + 8].hex())
                    for i in range(0, len(b), 8))


def near_marker(addr, span=8192):
    b = rd(int(addr) - span, 2 * span)
    if b is None:
        return "UNREADABLE"
    idx = b.find(b"postfield-marker")
    return "none" if idx < 0 else "%+d" % (idx - span)


def chunkinfo(to, to_end):
    # mapping_buffer header = 24 bytes (next/capa/used); glibc chunk header
    # = 16 bytes before the xmalloc pointer.
    chunk = int(to) - 40
    raw = rd(chunk + 8, 8)
    if raw is None:
        return "chunk=UNREADABLE"
    word = int.from_bytes(raw, "little")
    usable = (word & ~0x7) - 8
    off = int(to_end) - (int(to) - 24)
    return "chunk=%#x sizeword=%#x usable=%d oob_off=%d slack=%d" % (
        chunk, word, usable, off, usable - off)


class ToEndWatch(gdb.Breakpoint):
    def __init__(self, addr, callno_):
        self.addr = int(addr)
        self.callno = callno_
        self.seen = False
        self.late_seen = False
        super().__init__("*((unsigned char *)%d)" % self.addr,
                         type=gdb.BP_WATCHPOINT, wp_class=gdb.WP_WRITE,
                         internal=True)

    def stop(self):
        frame = gdb.newest_frame()
        name = frame.name() or "?"
        line = frame.find_sal().line
        raw = rd(self.addr, 1)
        byte = raw[0] if raw else -1
        if name == "case_map" and active_call == self.callno and not self.seen:
            self.seen = True
            traps.append((self.addr, byte))
            print("W379TRAP fold=%d call=%d addr=%#x byte=0x%02x frame=%s "
                  "line=%s region=%s dump=%s marker=%s" %
                  (self.callno, self.callno, self.addr, byte, name, line,
                   region(self.addr), dump(self.addr), near_marker(self.addr)))
        elif not self.late_seen:
            self.late_seen = True
            print("W379LATE fold=%d addr=%#x byte=0x%02x frame=%s active=%d "
                  "line=%s dump=%s" % (self.callno, self.addr, byte, name,
                                       active_call, line, dump(self.addr)))
        return False


class ReturnBreak(gdb.Breakpoint):
    def __init__(self):
        super().__init__("string.c:7850", internal=True)

    def stop(self):
        global active_call
        active_call = 0
        return False


class CallBreak(gdb.Breakpoint):
    def __init__(self):
        super().__init__("string.c:7839", internal=True)

    def stop(self):
        global callno, active_call, foldno
        callno += 1
        to = int(gdb.parse_and_eval("$rcx"))
        to_end = int(gdb.parse_and_eval("$r8"))
        capa = to_end - to
        if capa >= MIN_CAPA:
            foldno += 1
            print("W379CALL fold=%d call=%d to=%#x to_end=%#x capa=%d %s "
                  "region=%s pre=%s marker=%s" %
                  (foldno, callno, to, to_end, capa, chunkinfo(to, to_end),
                   region(to_end), dump(to_end), near_marker(to_end)))
            if foldno <= MAX_WATCH:
                ToEndWatch(to_end, callno)
                print("W379ARM fold=%d addr=%#x" % (foldno, to_end))
        active_call = callno
        return False


CallBreak()
ReturnBreak()
end
run
python
print("W379SUMMARY folds=%d traps=%d addrs=%s bytes=%s" %
      (foldno, len(traps), ",".join("%#x" % a for a, _ in traps),
       ",".join("0x%02x" % b for _, b in traps)))
end
quit
