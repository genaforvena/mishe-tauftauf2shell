set pagination off
set confirm off
set breakpoint pending on
set disable-randomization off
run
printf "=== INFERIOR STOPPED ===\n"
info registers rip rsp rbp rdi rax
bt 10
x/16gx $rsp-32
info proc mappings
kill
quit
