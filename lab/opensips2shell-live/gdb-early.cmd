set pagination off
set confirm off
set follow-fork-mode child
set detach-on-fork on
handle SIGSEGV stop print
handle SIGABRT stop print
run
printf "\n=== AT STOP ===\n"
info registers rip rsp rbp
x/16gx $rsp
bt
printf "\n=== END STOP ===\n"
quit
