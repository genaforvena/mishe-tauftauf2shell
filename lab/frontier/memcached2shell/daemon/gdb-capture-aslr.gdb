set disable-randomization off
set pagination off
set confirm off
set print pretty on
handle SIGSEGV stop nopass print
handle SIGBUS stop nopass print
handle SIGPIPE ignore nopass print
run
printf "\n=== POST-STOP MARKER ===\n"
printf "RIP=%p RSP=%p RBP=%p RBX=%p RCX=%p RAX=%p RDX=%p RDI=%p RSI=%p R12=%p\n", $rip, $rsp, $rbp, $rbx, $rcx, $rax, $rdx, $rdi, $rsi, $r12
info symbol $rip
info registers rbx rcx rip rsp rbp rax rdx rdi rsi r12
printf "--- memory at RBX ---\n"
x/12gx $rbx
printf "--- memory at RCX ---\n"
x/12gx $rcx
printf "--- stack ---\n"
x/8gx $rsp
printf "--- backtrace ---\n"
bt
printf "--- threads ---\n"
info threads
printf "\n=== END MARKER ===\n"
quit
