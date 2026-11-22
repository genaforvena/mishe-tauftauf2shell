set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "HIT-REGS pc=%p rbp=%p rsp=%p rdi=%p rsi=%p rdx=%p rcx=%p rax=%p rbx=%p\n", $pc, $rbp, $rsp, $rdi, $rsi, $rdx, $rcx, $rax, $rbx
x/12i $pc-24
info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11
printf "HIT-VAR i=%d &sender_name=%p\n", i, &sender_name
bt 5
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14001
