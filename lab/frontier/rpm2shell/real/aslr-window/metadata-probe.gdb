set pagination off
set breakpoint pending on
set confirm off
break main
run
python
import gdb
state={"done":0}
class CopyBP(gdb.Breakpoint):
    def stop(self):
        b=int(gdb.parse_and_eval("buf"))
        if b > 0x100000000:
            state["done"]=1
            nxt=int(gdb.parse_and_eval("*(void **)(buf+0x20)"))
            sz=int(gdb.parse_and_eval("*(unsigned long *)(buf+0x18)"))
            gdb.write("COPY_BUF=%s SIZE_Q=%s NEXT=%s\n"%(hex(b),hex(sz),hex(nxt)))
        return False
class VisitBP(gdb.Breakpoint):
    def stop(self):
        if state["done"]:
            gdb.write("VISIT=%s\n"%hex(int(gdb.parse_and_eval("$r14"))))
        return False
CopyBP("rpmcpioRead")
VisitBP("*(&lua_resume + 0x206)")
end
continue
