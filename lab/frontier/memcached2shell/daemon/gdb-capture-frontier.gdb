set disable-randomization off
set pagination off
set confirm off
set print pretty on
handle SIGSEGV stop nopass print
handle SIGBUS stop nopass print
handle SIGPIPE ignore nopass print
run
printf "\n=== POST-STOP MARKER ===\n"
printf "RIP=%p RBX=%p RCX=%p RAX=%p\n", $rip, $rbx, $rcx, $rax
info symbol $rip
info registers rbx rcx rip rsp rbp rax rdx rdi rsi r12
printf "--- crawler module at fault ---\n"
p active_crawler_mod.c.sfd
p active_crawler_mod.c.buflen
p active_crawler_mod.c.bufused
p active_crawler_mod.c.buf
printf "--- backtrace ---\n"
bt
printf "\n=== END MARKER ===\n"
quit
