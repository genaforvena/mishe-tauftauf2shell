set pagination off
set breakpoint pending on
set confirm off
set disable-randomization off
set $copy_done = 0
break main
run
python
visits = []
copy_done = 0
class PreBP(gdb.Breakpoint):
    def stop(self):
        try:
            buf = int(gdb.parse_and_eval("buf")) & ((1 << 64) - 1)
            q0 = int(gdb.parse_and_eval("*(void **)buf")) & ((1 << 64) - 1)
            q18 = int(gdb.parse_and_eval("*(void **)(buf+0x18)")) & ((1 << 64) - 1)
            q20 = int(gdb.parse_and_eval("*(void **)(buf+0x20)")) & ((1 << 64) - 1)
        except gdb.error:
            buf = q0 = q18 = q20 = 0
        readable = 0
        if q0:
            try:
                gdb.selected_inferior().read_memory(q0, 8)
                readable = 1
            except (gdb.error, MemoryError):
                pass
        gdb.write("PRE_BUF=%s PRE_Q0=%s PRE_READABLE=%d PRE_Q18=%s PRE_Q20=%s\n" %
                  (hex(buf), hex(q0), readable, hex(q18), hex(q20)))
        return False
PreBP("rpmfi.cc:2242")
class PostBP(gdb.Breakpoint):
    def stop(self):
        global copy_done
        copy_done = 1
        gdb.execute("set $post_q0 = *(void **)buf")
        gdb.execute("set $post_q20 = *(void **)(buf+0x20)")
        gdb.write("POST_Q0=%s POST_Q20=%s\n" %
                  (gdb.parse_and_eval("$post_q0"), gdb.parse_and_eval("$post_q20")))
        return False
PostBP("rpmfi.cc:2243")
class VisitBP(gdb.Breakpoint):
    def stop(self):
        if not copy_done:
            return False
        obj = int(gdb.parse_and_eval("$r14")) & ((1 << 64) - 1)
        visits.append(obj)
        q0 = int(gdb.parse_and_eval("$post_q0")) & ((1 << 64) - 1)
        q20 = int(gdb.parse_and_eval("$post_q20")) & ((1 << 64) - 1)
        if obj in (q0, q20):
            gdb.write("CHOSEN_VISIT=%s Q0=%s Q20=%s\n" %
                      (hex(obj), hex(q0), hex(q20)))
        return False
VisitBP("*(&lua_resume + 0x206)")
def on_exit(ev):
    try:
        q0 = int(gdb.parse_and_eval("$post_q0")) & ((1 << 64) - 1)
    except gdb.error:
        q0 = 0
    counts = []
    for bits in (8, 16, 32):
        mask = ((1 << 64) - 1) ^ ((1 << bits) - 1)
        matched = [v for v in visits if (v & mask) == (q0 & mask)]
        counts.append("MASK%d=%d" % (bits, len(matched)))
    gdb.write("VISIT_COUNT=%d %s\n" % (len(visits), " ".join(counts)))
gdb.events.exited.connect(on_exit)
end
continue
quit
