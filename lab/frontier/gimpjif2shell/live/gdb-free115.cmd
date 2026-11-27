# W335: no-shim live fault-site dump for the 8 KiB natural JIF overflow.
# GIMP starts only file-gif-load under gdb; no plugin byte, heap word or
# allocator state is modified. The stop handler records the freed chunk's
# size word and the heap-info address that glibc free+115 dereferences.
set pagination off
set confirm off
set print thread-events off
python
import gdb

def on_stop(ev):
    if not isinstance(ev, gdb.SignalEvent):
        return
    if ev.stop_signal not in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return
    inf = gdb.selected_inferior()
    print("=== W335 PLUGIN SIGNAL %s in inferior %s pid %s ===" %
          (ev.stop_signal, inf.num, inf.pid))
    gdb.execute("info registers rip rdi rsi rax rdx")
    gdb.execute("p/x &malloc")
    gdb.execute("p/x &free")
    gdb.execute("x/12i $rip-32")
    gdb.execute("x/4gx $rdi-16")
    rdi = int(gdb.parse_and_eval("$rdi"))
    size = int(gdb.parse_and_eval("*(unsigned long*)($rdi-8)"))
    rbp = rdi - 16
    aligned = rbp & 0xfffffffffc000000
    print("W335 freed_user=%#x size_word=%#x non_main_arena_bit=%d "
          "aligned_heapinfo=%#x" %
          (rdi, size, (size >> 2) & 1, aligned))
    try:
        gdb.execute("x/1gx %#x" % aligned)
    except gdb.error as exc:
        print("W335 heapinfo read failed: %s" % exc)
    gdb.execute("bt 8")

gdb.events.stop.connect(on_stop)
end
run
