set pagination off
set confirm off
run fill 10000 0x43
bt 8
info registers rip rsp rbp
x/48gx $rsp
quit
