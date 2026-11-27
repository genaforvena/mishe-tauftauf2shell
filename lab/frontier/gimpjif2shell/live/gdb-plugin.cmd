# Used as GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x <this> --args".
# GIMP invokes the wrapper with the plug-in executable and its wire args;
# "run" in this script passes those args straight to the plug-in. No plugin
# source, heap word or allocator state is modified by the debugger.
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
    print("=== W304 PLUGIN SIGNAL %s in inferior %s pid %s ===" %
          (ev.stop_signal, inf.num, inf.pid))
    gdb.execute("info registers rip rsp rdi rsi rax")
    gdb.execute("bt 25")

gdb.events.stop.connect(on_stop)
end
run
