set pagination off
set confirm off
set print pretty on
handle SIGSEGV stop nopass print
handle SIGBUS stop nopass print
handle SIGPIPE ignore nopass print
run
printf "\n=== POST-STOP MARKER ===\n"
printf "RIP=%p RSP=%p RBP=%p RCX=%p RAX=%p RDX=%p RDI=%p RSI=%p\n", $rip, $rsp, $rbp, $rcx, $rax, $rdx, $rdi, $rsi
info symbol $rip
info registers rcx rip rsp rbp rax rdx rdi rsi
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
