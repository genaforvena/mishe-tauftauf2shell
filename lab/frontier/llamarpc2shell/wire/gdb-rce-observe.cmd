set pagination off
set confirm off
run
info registers rdi rsi rdx rip
frame 1
info registers rdi rsi rdx rip
info proc mappings
bt 20
x/12gx $rsp-16
kill
quit
