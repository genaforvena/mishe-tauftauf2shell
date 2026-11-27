set pagination off
set confirm off
break recv_read_registers_res
run
frame 3
info frame
p/x &regs
continue
info registers rip
bt
quit
