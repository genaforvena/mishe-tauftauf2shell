set pagination off
set confirm off
set follow-fork-mode child
set detach-on-fork on
handle SIGSEGV stop print
run
printf "\n=== AT STOP ===\n"
info registers rip rsp rbp
x/4gx $rsp
bt 8
quit
