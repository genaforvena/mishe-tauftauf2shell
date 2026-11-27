set pagination off
set confirm off
break recv_read_registers_res
run
bt
frame 3
info frame
p/x &r_regs
continue
info registers rip
bt
quit
