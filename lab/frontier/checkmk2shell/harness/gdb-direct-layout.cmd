set pagination off
set confirm off
break direct_sink
run fill 100 0x43
p/x &message
p/x $rbp
p/x $rsp
x/8gx $rbp-32
x/8gx $rbp
quit
