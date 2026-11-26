# Stop when a chosen 64-bit payload value is walked as a live Lua GC pointer.
# Caller supplies: -ex 'set $want = 0x4141414141414141' and a `directory`
# command pointing at the pinned src/rpm/lib tree. No debugger-forced call.
set pagination off
set breakpoint pending on
set confirm off
set $copy_done = 0
break main
run

# Pinned copy site: record the adjacent object's first qword after the write.
break rpmfi.cc:2243
commands
  silent
  set $next_addr = buf + 0x20
  set $copy_done = 1
  printf "COPY_BUF=%p NEXT_ADDR=%p NEXT_AFTER=%p\n", buf, $next_addr, *(void **)$next_addr
  continue
end

# lua_resume+0x206 (liblua5.2.so.0) is a GC-list visit: %r14 is the object.
# Remember the last visited objects; stop on the chosen value and report
# whether the preceding object is the one whose qword the copy overwrote.
# Gate on the copy so a real heap address cannot match an earlier startup visit.
python
visits = []
class ChosenPtrBP(gdb.Breakpoint):
    def stop(self):
        obj = int(gdb.parse_and_eval("$r14")) & ((1 << 64) - 1)
        want = int(gdb.parse_and_eval("$want")) & ((1 << 64) - 1)
        visits.append(obj)
        if len(visits) > 8:
            visits.pop(0)
        if obj != want:
            return False
        if int(gdb.parse_and_eval("$copy_done")) != 1:
            return False
        prev = visits[-2] if len(visits) > 1 else 0
        try:
            naddr = int(gdb.parse_and_eval("$next_addr")) & ((1 << 64) - 1)
        except gdb.error:
            naddr = 0
        gdb.write("CHOSEN_PTR=%s PREV_OBJ=%s NEXT_ADDR=%s MATCH=%d\n" %
                  (hex(obj), hex(prev), hex(naddr), 1 if prev == naddr else 0))
        return True
ChosenPtrBP("*(&lua_resume + 0x206)")
end

continue
printf "=== STOPPED ON CHOSEN POINTER ===\n"
bt 5
info registers r14 rdx rip
x/4i $pc-8
printf "=== STEPI INTO THE DEREFERENCE ===\n"
stepi
bt 5
